"""
Suricata Integration Adapter

Reads alerts from Suricata IDS/IPS to boost LoneWarrior confidence scores.
This is OPTIONAL - LoneWarrior works perfectly without Suricata.
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class SuricataAdapter:
    """
    Suricata IDS/IPS integration for reading network alerts.
    
    Reads from:
    - EVE JSON log (eve.json) - preferred
    - Fast log (fast.log) - fallback
    - Unix socket - for real-time alerts
    """
    
    def __init__(self, config: Dict[str, Any], event_bus):
        self.config = config
        self.event_bus = event_bus
        
        # Integration config
        suricata_config = config.get('integrations', {}).get('suricata', {})
        self.enabled = suricata_config.get('enabled', False)
        self.eve_log = suricata_config.get('eve_log', '/var/log/suricata/eve.json')
        self.fast_log = suricata_config.get('fast_log', '/var/log/suricata/fast.log')
        self.socket_path = suricata_config.get('socket', '/var/run/suricata/suricata-command.socket')
        
        # State
        self._last_position = 0
        self._running = False
        self._thread = None
        self._lock = None  # Thread lock for shared state
        
        # Alert classification mapping
        self._severity_map = {
            1: 50,  # High priority
            2: 35,
            3: 20,
            4: 10   # Low priority
        }
    
    def start(self):
        """Start Suricata integration"""
        if not self.enabled:
            logger.debug("Suricata integration disabled")
            return
        
        self._running = True
        
        # Initialize thread lock
        import threading
        self._lock = threading.Lock()
        
        if Path(self.eve_log).exists():
            self._start_eve_watcher()
            logger.info(f"Suricata integration started (EVE: {self.eve_log})")
        elif Path(self.fast_log).exists():
            self._start_fast_watcher()
            logger.info(f"Suricata integration started (fast log)")
        else:
            self._running = False  # Reset state if no source available
            logger.warning("No Suricata log files found")
    
    def stop(self):
        """Stop Suricata integration"""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Suricata integration stopped")
    
    def _start_eve_watcher(self):
        """Watch Suricata EVE JSON log"""
        import threading
        import time
        
        def watch():
            try:
                with self._lock:
                    self._last_position = Path(self.eve_log).stat().st_size
            except Exception:
                with self._lock:
                    self._last_position = 0
            
            while self._running:
                try:
                    self._check_eve_entries()
                except Exception as e:
                    logger.error(f"Error reading Suricata EVE log: {e}")
                time.sleep(2)  # Check more frequently for IDS
        
        self._thread = threading.Thread(target=watch, daemon=True)
        self._thread.start()
    
    def _start_fast_watcher(self):
        """Watch Suricata fast log (fallback)"""
        import threading
        import time
        
        def watch():
            try:
                with self._lock:
                    self._last_position = Path(self.fast_log).stat().st_size
            except Exception:
                with self._lock:
                    self._last_position = 0
            
            while self._running:
                try:
                    self._check_fast_entries()
                except Exception as e:
                    logger.error(f"Error reading Suricata fast log: {e}")
                time.sleep(2)
        
        self._thread = threading.Thread(target=watch, daemon=True)
        self._thread.start()
    
    def _check_eve_entries(self):
        """Check for new EVE JSON entries"""
        path = Path(self.eve_log)
        if not path.exists():
            return
        
        with self._lock:
            current_size = path.stat().st_size
            if current_size <= self._last_position:
                if current_size < self._last_position:
                    self._last_position = 0
                return
            last_pos = self._last_position
        
        with open(path, 'r') as f:
            f.seek(last_pos)
            for line in f:
                line = line.strip()
                if line:
                    try:
                        event = json.loads(line)
                        # Only process alert events
                        if event.get('event_type') == 'alert':
                            self._process_eve_alert(event)
                    except json.JSONDecodeError:
                        continue
            with self._lock:
                self._last_position = f.tell()
    
    def _check_fast_entries(self):
        """Check for new fast log entries"""
        path = Path(self.fast_log)
        if not path.exists():
            return
        
        with self._lock:
            current_size = path.stat().st_size
            if current_size <= self._last_position:
                if current_size < self._last_position:
                    self._last_position = 0
                return
            last_pos = self._last_position
        
        with open(path, 'r') as f:
            f.seek(last_pos)
            for line in f:
                line = line.strip()
                if line:
                    self._process_fast_alert(line)
            with self._lock:
                self._last_position = f.tell()
    
    def _process_eve_alert(self, event: Dict[str, Any]):
        """Process Suricata EVE JSON alert"""
        try:
            alert = event.get('alert', {})
            
            signature_id = alert.get('signature_id')
            signature = alert.get('signature', 'Unknown alert')
            severity = alert.get('severity', 3)
            category = alert.get('category', 'Unknown')
            
            # Network info
            src_ip = event.get('src_ip')
            dest_ip = event.get('dest_ip')
            src_port = event.get('src_port')
            dest_port = event.get('dest_port')
            proto = event.get('proto')
            
            # Map severity to confidence boost
            confidence_boost = self._severity_map.get(severity, 15)
            
            event_data = {
                'source': 'suricata',
                'signature_id': signature_id,
                'signature': signature,
                'severity': severity,
                'category': category,
                'confidence_boost': confidence_boost,
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'src_port': src_port,
                'dest_port': dest_port,
                'protocol': proto,
                'timestamp': event.get('timestamp'),
                'flow_id': event.get('flow_id')
            }
            
            from lonewarrior.core.event_bus import EventPriority
            priority = EventPriority.HIGH if severity <= 2 else EventPriority.NORMAL
            
            self.event_bus.publish(
                'external_signal',
                event_data,
                priority,
                'SuricataAdapter'
            )
            
            logger.debug(f"Suricata alert: {signature_id} - {signature[:50]}")
            
        except Exception as e:
            logger.error(f"Error processing Suricata EVE alert: {e}")
    
    def _process_fast_alert(self, line: str):
        """Process Suricata fast log alert"""
        try:
            # Fast log format:
            # MM/DD/YYYY-HH:MM:SS.UUUUUU  [**] [1:2000001:1] ET SCAN ... [**] [Classification: ...] [Priority: N] {PROTO} SRC -> DST
            
            import re
            
            # Extract priority
            priority_match = re.search(r'\[Priority: (\d+)\]', line)
            priority = int(priority_match.group(1)) if priority_match else 3
            
            # Extract signature
            sig_match = re.search(r'\[\*\*\] \[([^\]]+)\] (.+?) \[\*\*\]', line)
            signature_id = sig_match.group(1) if sig_match else None
            signature = sig_match.group(2) if sig_match else line[:100]
            
            # Extract IPs
            ip_match = re.search(r'\{(\w+)\} ([\d.]+):?(\d*) -> ([\d.]+):?(\d*)', line)
            if ip_match:
                proto = ip_match.group(1)
                src_ip = ip_match.group(2)
                src_port = ip_match.group(3) or None
                dest_ip = ip_match.group(4)
                dest_port = ip_match.group(5) or None
            else:
                proto = src_ip = dest_ip = None
                src_port = dest_port = None
            
            confidence_boost = self._severity_map.get(priority, 15)
            
            event_data = {
                'source': 'suricata',
                'signature_id': signature_id,
                'signature': signature,
                'severity': priority,
                'confidence_boost': confidence_boost,
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'src_port': src_port,
                'dest_port': dest_port,
                'protocol': proto
            }
            
            from lonewarrior.core.event_bus import EventPriority
            evt_priority = EventPriority.HIGH if priority <= 2 else EventPriority.NORMAL
            
            self.event_bus.publish(
                'external_signal',
                event_data,
                evt_priority,
                'SuricataAdapter'
            )
            
        except Exception as e:
            logger.error(f"Error processing Suricata fast alert: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get adapter status"""
        return {
            'enabled': self.enabled,
            'running': self._running,
            'eve_log': self.eve_log,
            'fast_log': self.fast_log
        }
