"""
ModSecurity Integration Adapter

Reads alerts from ModSecurity WAF to boost LoneWarrior confidence scores.
This is OPTIONAL - LoneWarrior works perfectly without ModSecurity.
"""

import logging
import re
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ModSecurityAdapter:
    """
    ModSecurity WAF integration for reading WAF alerts.
    
    Reads from:
    - ModSecurity audit log (modsec_audit.log)
    - OR Apache/Nginx error logs with ModSecurity entries
    
    Supports:
    - ModSecurity 2.x (Apache)
    - ModSecurity 3.x (libmodsecurity)
    """
    
    def __init__(self, config: Dict[str, Any], event_bus):
        self.config = config
        self.event_bus = event_bus
        
        # Integration config
        modsec_config = config.get('integrations', {}).get('modsecurity', {})
        self.enabled = modsec_config.get('enabled', False)
        self.audit_log = modsec_config.get('audit_log', '/var/log/modsec_audit.log')
        self.error_log = modsec_config.get('error_log', '/var/log/apache2/error.log')
        
        # State
        self._last_position = 0
        self._running = False
        self._thread = None
        
        # Patterns for parsing
        self._audit_pattern = re.compile(
            r'\[id "(\d+)"\].*\[severity "(\w+)"\].*\[msg "([^"]+)"\]'
        )
        self._ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    
    def start(self):
        """Start ModSecurity integration"""
        if not self.enabled:
            logger.debug("ModSecurity integration disabled")
            return
        
        self._running = True
        self._start_log_watcher()
        logger.info(f"ModSecurity integration started")
    
    def stop(self):
        """Stop ModSecurity integration"""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("ModSecurity integration stopped")
    
    def _start_log_watcher(self):
        """Watch ModSecurity log files"""
        import threading
        import time
        
        def watch():
            # Determine which file to watch
            log_path = None
            if Path(self.audit_log).exists():
                log_path = self.audit_log
            elif Path(self.error_log).exists():
                log_path = self.error_log
            else:
                logger.warning("No ModSecurity log files found")
                return
            
            try:
                self._last_position = Path(log_path).stat().st_size
            except Exception:
                self._last_position = 0
            
            while self._running:
                try:
                    self._check_new_entries(log_path)
                except Exception as e:
                    logger.error(f"Error reading ModSecurity log: {e}")
                time.sleep(5)
        
        self._thread = threading.Thread(target=watch, daemon=True)
        self._thread.start()
    
    def _check_new_entries(self, log_path: str):
        """Check for new ModSecurity entries"""
        path = Path(log_path)
        if not path.exists():
            return
        
        current_size = path.stat().st_size
        if current_size <= self._last_position:
            if current_size < self._last_position:
                self._last_position = 0
            return
        
        with open(path, 'r', errors='ignore') as f:
            f.seek(self._last_position)
            buffer = ""
            
            for line in f:
                # ModSecurity entries can span multiple lines
                if 'ModSecurity' in line or 'modsecurity' in line.lower():
                    if buffer:
                        self._process_entry(buffer)
                    buffer = line
                elif buffer:
                    buffer += line
                    # Check if entry is complete
                    if line.strip() == '' or '--' in line:
                        self._process_entry(buffer)
                        buffer = ""
            
            # Process remaining buffer
            if buffer:
                self._process_entry(buffer)
            
            self._last_position = f.tell()
    
    def _process_entry(self, entry: str):
        """Process ModSecurity log entry"""
        try:
            # Extract rule ID, severity, and message
            match = self._audit_pattern.search(entry)
            
            rule_id = None
            severity = 'UNKNOWN'
            message = 'ModSecurity alert'
            
            if match:
                rule_id = match.group(1)
                severity = match.group(2)
                message = match.group(3)
            else:
                # Try simpler extraction
                if 'id:' in entry:
                    id_match = re.search(r'id:(\d+)', entry)
                    if id_match:
                        rule_id = id_match.group(1)
            
            # Extract source IP - look for common patterns
            # Priority: client header, X-Forwarded-For, first IP after client indicator
            source_ip = None
            
            # Look for explicit client IP patterns
            client_patterns = [
                r'\[client\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',
                r'client:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                r'srcip:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                r'X-Forwarded-For:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            ]
            for pattern in client_patterns:
                client_match = re.search(pattern, entry, re.IGNORECASE)
                if client_match:
                    source_ip = client_match.group(1)
                    break
            
            # Fallback to first IP in log (less reliable)
            if not source_ip:
                all_ips = self._ip_pattern.findall(entry)
                # Filter out common non-client IPs (localhost, private when likely server)
                for ip in all_ips:
                    if not ip.startswith('127.') and ip != '0.0.0.0':
                        source_ip = ip
                        break
            
            # Map severity to confidence boost
            severity_map = {
                'CRITICAL': 45,
                'ERROR': 35,
                'WARNING': 25,
                'NOTICE': 15,
                'INFO': 5,
                'DEBUG': 0
            }
            confidence_boost = severity_map.get(severity.upper(), 20)
            
            # Determine attack type from rule ID ranges (OWASP CRS)
            attack_type = self._classify_rule(rule_id)
            
            event_data = {
                'source': 'modsecurity',
                'rule_id': rule_id,
                'severity': severity,
                'message': message,
                'confidence_boost': confidence_boost,
                'source_ip': source_ip,
                'attack_type': attack_type,
                'raw_entry': entry[:500]  # Truncate
            }
            
            from lonewarrior.core.event_bus import EventPriority
            self.event_bus.publish(
                'external_signal',
                event_data,
                EventPriority.NORMAL,
                'ModSecurityAdapter'
            )
            
            logger.debug(f"ModSecurity alert: rule {rule_id} ({severity})")
            
        except Exception as e:
            logger.error(f"Error processing ModSecurity entry: {e}")
    
    def _classify_rule(self, rule_id: Optional[str]) -> str:
        """Classify attack type from OWASP CRS rule ID"""
        if not rule_id:
            return 'unknown'
        
        try:
            rid = int(rule_id)
            if 941000 <= rid < 942000:
                return 'xss'
            elif 942000 <= rid < 943000:
                return 'sql_injection'
            elif 943000 <= rid < 944000:
                return 'session_fixation'
            elif 930000 <= rid < 931000:
                return 'lfi'  # Local File Inclusion
            elif 931000 <= rid < 932000:
                return 'rfi'  # Remote File Inclusion
            elif 932000 <= rid < 933000:
                return 'rce'  # Remote Code Execution
            elif 933000 <= rid < 934000:
                return 'php_injection'
            elif 920000 <= rid < 921000:
                return 'protocol_violation'
            elif 913000 <= rid < 914000:
                return 'scanner_detection'
            else:
                return 'other'
        except (ValueError, TypeError):
            return 'unknown'
    
    def get_status(self) -> Dict[str, Any]:
        """Get adapter status"""
        return {
            'enabled': self.enabled,
            'running': self._running,
            'audit_log': self.audit_log,
            'error_log': self.error_log
        }
