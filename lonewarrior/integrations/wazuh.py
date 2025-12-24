"""
Wazuh Integration Adapter

Reads alerts from Wazuh SIEM/EDR to boost LoneWarrior confidence scores.
This is OPTIONAL - LoneWarrior works perfectly without Wazuh.
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class WazuhAdapter:
    """
    Wazuh integration for reading SIEM/EDR alerts.
    
    Reads from:
    - Wazuh alerts log file (/var/ossec/logs/alerts/alerts.json)
    - OR Wazuh API if configured
    
    Publishes events that boost detection confidence.
    """
    
    def __init__(self, config: Dict[str, Any], event_bus):
        self.config = config
        self.event_bus = event_bus
        
        # Integration config
        wazuh_config = config.get('integrations', {}).get('wazuh', {})
        self.enabled = wazuh_config.get('enabled', False)
        self.alerts_path = wazuh_config.get('alerts_path', '/var/ossec/logs/alerts/alerts.json')
        self.api_url = wazuh_config.get('api_url')
        self.api_user = wazuh_config.get('api_user')
        self.api_password = wazuh_config.get('api_password')
        self.verify_ssl = wazuh_config.get('verify_ssl', True)  # SSL verification enabled by default
        
        # State
        self._last_position = 0
        self._running = False
        self._thread = None
        self._lock = None  # Thread lock for shared state
        self._seen_alerts = set()  # Deduplication for API polling
        self._max_seen_alerts = 1000  # Limit memory usage
    
    def start(self):
        """Start Wazuh integration"""
        if not self.enabled:
            logger.debug("Wazuh integration disabled")
            return
        
        self._running = True
        
        # Initialize thread lock
        import threading
        self._lock = threading.Lock()
        
        if Path(self.alerts_path).exists():
            self._start_file_watcher()
            logger.info(f"Wazuh integration started (watching {self.alerts_path})")
        elif self.api_url:
            self._start_api_poller()
            logger.info(f"Wazuh integration started (API: {self.api_url})")
        else:
            self._running = False  # Reset state if no source available
            logger.warning("Wazuh enabled but no alerts file or API configured")
    
    def stop(self):
        """Stop Wazuh integration"""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Wazuh integration stopped")
    
    def _start_file_watcher(self):
        """Watch Wazuh alerts file for new entries"""
        import threading
        import time
        
        def watch():
            # Get initial file size with lock
            try:
                with self._lock:
                    self._last_position = Path(self.alerts_path).stat().st_size
            except Exception:
                with self._lock:
                    self._last_position = 0
            
            while self._running:
                try:
                    self._check_new_alerts()
                except Exception as e:
                    logger.error(f"Error reading Wazuh alerts: {e}")
                time.sleep(5)  # Check every 5 seconds
        
        self._thread = threading.Thread(target=watch, daemon=True)
        self._thread.start()
    
    def _start_api_poller(self):
        """Poll Wazuh API for alerts"""
        import threading
        import time
        
        def poll():
            while self._running:
                try:
                    self._fetch_api_alerts()
                except Exception as e:
                    logger.error(f"Error polling Wazuh API: {e}")
                time.sleep(30)  # Poll every 30 seconds
        
        self._thread = threading.Thread(target=poll, daemon=True)
        self._thread.start()
    
    def _check_new_alerts(self):
        """Check for new alerts in file"""
        path = Path(self.alerts_path)
        if not path.exists():
            return
        
        with self._lock:
            current_size = path.stat().st_size
            if current_size <= self._last_position:
                if current_size < self._last_position:
                    # File was rotated
                    self._last_position = 0
                return
            last_pos = self._last_position
        
        with open(path, 'r') as f:
            f.seek(last_pos)
            for line in f:
                line = line.strip()
                if line:
                    try:
                        alert = json.loads(line)
                        self._process_alert(alert)
                    except json.JSONDecodeError:
                        continue
            with self._lock:
                self._last_position = f.tell()
    
    def _fetch_api_alerts(self):
        """Fetch alerts from Wazuh API"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            # Get JWT token
            auth_url = f"{self.api_url}/security/user/authenticate"
            resp = requests.post(
                auth_url,
                auth=HTTPBasicAuth(self.api_user, self.api_password),
                verify=self.verify_ssl,  # Use configurable SSL verification
                timeout=10
            )
            
            if resp.status_code != 200:
                logger.error(f"Wazuh auth failed: {resp.status_code}")
                return
            
            token = resp.json().get('data', {}).get('token')
            
            # Fetch recent alerts
            alerts_url = f"{self.api_url}/alerts?limit=50&sort=-timestamp"
            resp = requests.get(
                alerts_url,
                headers={'Authorization': f'Bearer {token}'},
                verify=self.verify_ssl,  # Use configurable SSL verification
                timeout=30
            )
            
            if resp.status_code == 200:
                alerts = resp.json().get('data', {}).get('affected_items', [])
                for alert in alerts:
                    # Deduplication: skip already-seen alerts
                    alert_id = alert.get('id') or alert.get('_id') or hash(json.dumps(alert, sort_keys=True))
                    if alert_id in self._seen_alerts:
                        continue
                    
                    self._seen_alerts.add(alert_id)
                    # Limit memory usage
                    if len(self._seen_alerts) > self._max_seen_alerts:
                        # Remove oldest half
                        self._seen_alerts = set(list(self._seen_alerts)[self._max_seen_alerts // 2:])
                    
                    self._process_alert(alert)
                    
        except ImportError:
            logger.warning("requests library not installed for Wazuh API")
        except Exception as e:
            logger.error(f"Wazuh API error: {e}")
    
    def _process_alert(self, alert: Dict[str, Any]):
        """Process Wazuh alert and publish to event bus"""
        try:
            rule = alert.get('rule', {})
            rule_id = rule.get('id')
            level = rule.get('level', 0)
            description = rule.get('description', '')
            
            # Map Wazuh levels to confidence boost
            # Wazuh levels: 0-15, higher = more severe
            confidence_boost = min(level * 5, 50)  # Max 50% boost
            
            # Extract relevant data
            agent = alert.get('agent', {})
            data = alert.get('data', {})
            
            event_data = {
                'source': 'wazuh',
                'rule_id': rule_id,
                'level': level,
                'description': description,
                'confidence_boost': confidence_boost,
                'agent_name': agent.get('name'),
                'agent_ip': agent.get('ip'),
                'srcip': data.get('srcip'),
                'dstip': data.get('dstip'),
                'srcport': data.get('srcport'),
                'dstport': data.get('dstport'),
                'user': data.get('srcuser') or data.get('dstuser'),
                'raw_alert': alert
            }
            
            # Publish as supplementary signal (never authoritative)
            from lonewarrior.core.event_bus import EventPriority
            self.event_bus.publish(
                'external_signal',
                event_data,
                EventPriority.NORMAL,
                'WazuhAdapter'
            )
            
            logger.debug(f"Wazuh alert processed: {rule_id} (level {level})")
            
        except Exception as e:
            logger.error(f"Error processing Wazuh alert: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get adapter status"""
        return {
            'enabled': self.enabled,
            'running': self._running,
            'alerts_path': self.alerts_path,
            'api_configured': bool(self.api_url)
        }
