"""
Threat Intel Analyzer - Converts threat intel signals into detections/actions.

V2 Enhancement: Integrates external threat feeds (AbuseIPDB, Project Honey Pot)
"""

import logging
import os
from typing import Dict, Any
from datetime import datetime, timezone

from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, DetectionType, EventType, ThreatIntel
from lonewarrior.core.state_manager import StateManager

logger = logging.getLogger(__name__)


def get_abuseipdb_api_key() -> str:
    """Get AbuseIPDB API key from environment or config"""
    # Priority: 1. Environment variable, 2. Config file
    env_key = os.getenv('ABUSEIPDB_API_KEY')
    if env_key and env_key != 'your_api_key_here':
        return env_key

    # Fall back to config (for backwards compatibility)
    # Note: In production, the config should reference the env file
    return ''


class ThreatIntelAnalyzer:
    """
    V2: Enhanced threat intel with external feed integration
    - Local auth failure tracking (builds reputation)
    - External threat feeds: AbuseIPDB, Project Honey Pot
    - Confidence boosted by external intel hits
    """

    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager

        # External threat intel module
        if config.get('threat_intel', {}).get('external_feeds', {}).get('enabled', False):
            from lonewarrior.analyzers.external_threat_intel import ExternalThreatIntel
            self.external_intel = ExternalThreatIntel(config, database, event_bus)
        else:
            self.external_intel = None

        self.event_bus.subscribe(EventType.AUTH_FAILURE.value, self.handle_auth_failure)

    def start(self):
        logger.info("Threat intel analyzer started")
        if self.external_intel:
            self.external_intel.start()

    def stop(self):
        logger.info("Threat intel analyzer stopped")
        if self.external_intel:
            self.external_intel.stop()

    def handle_auth_failure(self, event: InternalEvent):
        """Handle auth failure and check external threat intel"""
        data = event.data
        ip = data.get("ip")
        if not ip:
            return

        # Get or create local threat intel entry
        threat = self.db.get_threat_intel(ip)
        if not threat:
            threat = ThreatIntel(
                ip_address=ip,
                reputation_score=0,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                is_blacklisted=False,
                failed_auth_count=1,
                scan_detected=False,
                notes=""
            )
            self.db.upsert_threat_intel(threat)

        # Update local threat intel with auth failure
        threat.failed_auth_count += 1
        self.db.upsert_threat_intel(threat)

        # Check external threat intel
        external_threat = self.external_intel.check_ip(ip) if self.external_intel else None

        # Calculate confidence
        base_confidence = min(90.0, float(max(threat.reputation_score, 30)))

        # Boost confidence for external intel hits
        if external_threat:
            # AbuseIPDB hit
            if 'abuseipdb' in external_threat:
                abuse_confidence = external_threat['abuseipdb']['abuse_confidence']
                boost = self.config.get('threat_intel', {}).get('external_feeds', {}).get('abuseipdb', {}).get('confidence_boost', 15)
                base_confidence += min(boost, abuse_confidence)
                logger.info(f"AbuseIPDB hit for {ip}: confidence={abuse_confidence}, reports={external_threat['abuseipdb']['reports_count']}")

            # Project Honey Pot hit
            if 'project_honeypot' in external_threat:
                boost = self.config.get('threat_intel', {}).get('external_feeds', {}).get('project_honeypot', {}).get('confidence_boost', 20)
                base_confidence += boost
                logger.info(f"Project Honey Pot hit for {ip}: seen_count={external_threat['project_honeypot']['seen_count']}")

        # Threshold check - only generate detection after a few failures OR external intel hit
        if threat.failed_auth_count < 5 and not external_threat:
            return

        # Determine description
        if external_threat:
            parts = []
            if 'abuseipdb' in external_threat:
                parts.append(f"AbuseIPDB reports: {external_threat['abuseipdb']['reports_count']}")
            if 'project_honeypot' in external_threat:
                parts.append(f"Project Honey Pot: seen")
            description = f"Suspicious IP {ip}: {', '.join(parts)} (auth_failures={threat.failed_auth_count})"
        else:
            description = f"Suspicious auth failures from {ip} (failed={threat.failed_auth_count}, rep={threat.reputation_score})"

        # Create detection
        detection = Detection(
            detection_type=DetectionType.THREAT_INTEL_HIT.value,
            description=description,
            confidence_score=base_confidence,
            data={"ip": ip, "failed_auth_count": threat.failed_auth_count, "reputation_score": threat.reputation_score, "external_threat": external_threat},
        )
        detection.id = self.db.insert_detection(detection)

        self.event_bus.publish(
            "detection_created",
            {
                "detection_id": detection.id,
                "type": detection.detection_type,
                "description": description,
                "confidence": base_confidence,
            },
            EventPriority.HIGH if base_confidence >= self.config["confidence"]["contain"] else EventPriority.NORMAL,
            "ThreatIntelAnalyzer",
        )



