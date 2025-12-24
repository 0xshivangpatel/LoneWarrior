"""
External Threat Intel - Fetches threat intelligence from external sources

Integrates with:
- AbuseIPDB (API key required)
- Project Honey Pot (free, no API key required)
"""

import logging
import os
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone
import requests

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import ThreatIntel
from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority


logger = logging.getLogger(__name__)


class ExternalThreatIntel:
    """Fetches threat intelligence from external sources"""

    def __init__(self, config: Dict[str, Any], database: Database, event_bus: EventBus):
        self.config = config
        self.db = database
        self.event_bus = event_bus

        self._running = False

    def start(self):
        """Start external threat intel updates"""
        self._running = True
        logger.info("External threat intel started")

        # Initial load of threat intel
        if self.config.get('threat_intel', {}).get('external_feeds', {}).get('enabled', False):
            self._load_initial_threat_intel()

    def stop(self):
        """Stop external threat intel updates"""
        self._running = False
        logger.info("External threat intel stopped")

    def _get_abuseipdb_key(self) -> Optional[str]:
        """Get AbuseIPDB API key from environment or config"""
        # Priority: 1. Environment variable, 2. Config file
        env_key = os.getenv('ABUSEIPDB_API_KEY')

        # Don't use placeholder values
        if env_key and env_key not in ['your_api_key_here', '']:
            return env_key

        # Fall back to config (for backwards compatibility, but not recommended)
        config_key = self.config.get('threat_intel', {}).get('external_feeds', {}).get('abuseipdb', {}).get('api_key', '')

        if config_key and config_key not in ['your_api_key_here', '']:
            return config_key

        return None

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Check an IP against external threat intelligence sources.

        Args:
            ip: IP address to check

        Returns:
            Dict with threat intel data, or None if IP is clean
        """
        threat_data = {}

        # Check AbuseIPDB
        if self.config['threat_intel']['external_feeds'].get('abuseipdb', {}).get('enabled', False):
            abuseipdb_data = self._check_abuseipdb(ip)
            if abuseipdb_data:
                threat_data['abuseipdb'] = abuseipdb_data

        # Check Project Honey Pot
        if self.config['threat_intel']['external_feeds'].get('project_honeypot', {}).get('enabled', False):
            honeypot_data = self._check_project_honeypot(ip)
            if honeypot_data:
                threat_data['project_honeypot'] = honeypot_data

        return threat_data if threat_data else None

    def _check_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP against AbuseIPDB API"""
        api_key = self._get_abuseipdb_key()

        if not api_key:
            logger.debug(f"AbuseIPDB API key not configured, skipping check for {ip}")
            return None

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key}
            params = {
                "ipAddress": ip,
                "maxAgeInDays": self.config.get('threat_intel', {}).get('external_feeds', {}).get('abuseipdb', {}).get('max_age_in_days', 90)
            }

            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()

            data = response.json().get('data', {})
            if not data:
                return None

            return {
                'abuse_confidence': data.get('abuseConfidence', 0),
                'is_whitelisted': data.get('isWhitelisted', False),
                'reports_count': len(data.get('reports', [])),
                'last_report': data.get('lastReportAt'),
                'source': 'abuseipdb'
            }

        except requests.RequestException as e:
            logger.warning(f"Failed to check AbuseIPDB for {ip}: {e}")
            return None

    def _check_project_honeypot(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check IP against Project Honey Pot"""
        try:
            url = f"https://check.projecthoneypot.org/api/ip/{ip}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            data = response.json()

            # Project Honey Pot returns: {"ip": "...", "last_seen": "...", "count": N}
            if data.get('count', 0) == 0:
                return None

            return {
                'seen_count': data.get('count', 0),
                'last_seen': data.get('last_seen'),
                'source': 'project_honeypot'
            }

        except requests.RequestException as e:
            logger.warning(f"Failed to check Project Honey Pot for {ip}: {e}")
            return None

    def _load_initial_threat_intel(self):
        """Load initial threat intel from Project Honey Pot (IP list download)"""
        if not self.config['threat_intel']['external_feeds'].get('project_honeypot', {}).get('enabled', False):
            return

        try:
            logger.info("Loading Project Honey Pot threat intel...")
            url = "https://raw.githubusercontent.com/projecthoneypot/ioc-csv/master/ioc.csv"

            response = requests.get(url, timeout=30)
            response.raise_for_status()

            lines = response.text.split('\n')
            count = 0

            for line in lines[1:]:  # Skip header
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    ip = parts[0].strip().strip('"')
                    threat_type = parts[1].strip().strip('"') if len(parts) > 1 else 'unknown'

                    if ip and self._is_valid_ip(ip):
                        # Check if IP already in database
                        existing = self.db.get_threat_intel(ip)

                        # Calculate reputation score based on threat type
                        reputation = self._calculate_honeypot_reputation(threat_type)

                        if existing:
                            # Update existing entry with higher reputation
                            if reputation > existing.reputation_score:
                                existing.reputation_score = reputation
                                existing.scan_detected = True
                                existing.notes = f"Project Honey Pot: {threat_type}"
                                self.db.upsert_threat_intel(existing)
                                count += 1
                        else:
                            # Create new threat intel entry
                            threat = ThreatIntel(
                                ip_address=ip,
                                reputation_score=reputation,
                                first_seen=datetime.now(timezone.utc),
                                last_seen=datetime.now(timezone.utc),
                                is_blacklisted=False,  # Don't auto-blacklist, let LoneWarrior decide
                                failed_auth_count=0,
                                scan_detected=True,
                                notes=f"Project Honey Pot: {threat_type}"
                            )
                            self.db.upsert_threat_intel(threat)
                            count += 1

            logger.info(f"Loaded {count} IPs from Project Honey Pot")

        except requests.RequestException as e:
            logger.warning(f"Failed to load Project Honey Pot threat intel: {e}")

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _calculate_honeypot_reputation(self, threat_type: str) -> int:
        """Calculate reputation score based on honeypot threat type"""
        threat_scores = {
            'spam': 30,
            'c2': 80,
            'scanner': 50,
            'exploit': 90,
            'bot': 85,
            'other': 40
        }

        for key, score in threat_scores.items():
            if key.lower() in threat_type.lower():
                return score

        return 50  # Default score for unknown threat types

    def run_periodic_update(self):
        """Periodic update of threat intel database"""
        if not self._running:
            return

        check_interval = self.config['threat_intel']['external_feeds'].get('check_interval', 3600)

        while self._running:
            try:
                logger.info("Running periodic threat intel update...")

                # Reload Project Honey Pot list periodically
                self._load_initial_threat_intel()

                # Sleep for next check
                time.sleep(check_interval)

            except Exception as e:
                logger.error(f"Error in periodic threat intel update: {e}")
                time.sleep(300)  # Wait 5 minutes before retry
