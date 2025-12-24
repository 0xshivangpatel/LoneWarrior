"""
Auth Collector - Monitors authentication events
"""

import os
import re
from pathlib import Path
from typing import Dict, Any, List, Optional

from lonewarrior.collectors.base import BaseCollector
from lonewarrior.storage.models import Event, EventType
from lonewarrior.core.event_bus import EventPriority


class AuthCollector(BaseCollector):
    """Collects authentication events from system logs"""
    
    # Common auth log patterns
    SSH_SUCCESS_PATTERN = r'Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
    SSH_FAILURE_PATTERN = r'Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)'
    SUDO_PATTERN = r'(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>\S+) ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)'
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log_paths = self._find_auth_logs()
        self.log_positions: Dict[str, int] = {}
        self.log_inodes: Dict[str, int] = {}  # Track file inodes for rotation detection
        self.initial_scan_complete = False

        # Track failed auth attempts for brute force detection
        self.failed_auth_tracking: Dict[str, List] = {}  # ip -> list of timestamps

        # Initialize positions and perform initial scan
        for log_path in self.log_paths:
            if os.path.exists(log_path):
                self._perform_initial_scan(log_path)
                self._update_log_position(log_path)

        self.initial_scan_complete = True
    
    def _get_collection_interval(self) -> int:
        return self.config['collection']['auth_log_interval']
    
    def _perform_initial_scan(self, log_path: str):
        """
        Perform initial scan of auth log to catch recent authentication events.
        This runs once on startup to ensure we don't miss events that occurred before LoneWarrior started.
        """
        try:
            # Read last 2000 lines to catch recent events without overwhelming system
            # Increased from 1000 to better capture attack patterns
            with open(log_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                recent_lines = lines[-2000:] if len(lines) > 2000 else lines

            self.logger.info(f"Performing initial scan of {log_path}: {len(recent_lines)} recent lines")

            for line in recent_lines:
                self._parse_log_line(line.strip())

        except Exception as e:
            self.logger.error(f"Error during initial scan of {log_path}: {e}")
    
    def _find_auth_logs(self) -> List[str]:
        """Find authentication log files"""
        possible_paths = [
            '/var/log/auth.log',      # Debian/Ubuntu
            '/var/log/secure',         # RHEL/CentOS
            '/var/log/syslog',         # General syslog
            '/var/log/messages',        # General messages (common on Kali)
            '/var/log/kern.log',       # Kernel log
        ]

        logs = []
        for p in possible_paths:
            if os.path.exists(p):
                self.logger.info(f"Found auth log: {p}")
                logs.append(p)

        if not logs:
            self.logger.warning("No auth log files found in standard locations")

        return logs

    def _get_file_inode(self, file_path: str) -> int:
        """Get inode of a file for rotation detection"""
        try:
            stat_result = os.stat(file_path)
            return stat_result.st_ino
        except OSError:
            return 0

    def _update_log_position(self, log_path: str):
        """Update position tracking for a log file"""
        self.log_positions[log_path] = os.path.getsize(log_path)
        self.log_inodes[log_path] = self._get_file_inode(log_path)
    
    def collect(self):
        """Collect new authentication events from logs"""
        for log_path in self.log_paths:
            try:
                self._process_log_file(log_path)
            except Exception as e:
                self.logger.error(f"Error processing {log_path}: {e}")
    
    def _process_log_file(self, log_path: str):
        """Process a log file for new entries"""
        if not os.path.exists(log_path):
            return

        current_size = os.path.getsize(log_path)
        current_inode = self._get_file_inode(log_path)
        last_position = self.log_positions.get(log_path, 0)
        last_inode = self.log_inodes.get(log_path, 0)

        # Check for log rotation (inode changed or file shrank significantly)
        log_rotated = False
        if current_inode != last_inode and last_inode != 0:
            # File was rotated - read from start
            self.logger.info(f"Log rotation detected for {log_path} (inode changed)")
            log_rotated = True
        elif current_size < last_position - 1000:  # Allow for small truncations
            # File was truncated significantly
            self.logger.info(f"Log truncation detected for {log_path}")
            log_rotated = True

        if log_rotated:
            # Full read on rotation to catch all entries in new file
            last_position = 0

        # No new data
        if current_size == last_position:
            return

        # Read new lines
        try:
            with open(log_path, 'r', errors='ignore') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                self.log_positions[log_path] = f.tell()
                self.log_inodes[log_path] = current_inode

            # Parse new lines
            for line in new_lines:
                self._parse_log_line(line.strip())
        except Exception as e:
            self.logger.error(f"Error reading {log_path}: {e}")
    
    def _parse_log_line(self, line: str):
        """Parse a log line for auth events"""
        # SSH success
        match = re.search(self.SSH_SUCCESS_PATTERN, line)
        if match:
            self._handle_ssh_success(match.groupdict())
            return
        
        # SSH failure
        match = re.search(self.SSH_FAILURE_PATTERN, line)
        if match:
            self._handle_ssh_failure(match.groupdict())
            return
        
        # Sudo usage
        match = re.search(self.SUDO_PATTERN, line)
        if match:
            self._handle_sudo(match.groupdict())
            return
    
    def _handle_ssh_success(self, data: Dict[str, str]):
        """Handle successful SSH login"""
        event_data = {
            'event': 'ssh_success',
            'user': data['user'],
            'ip': data['ip'],
            'port': data['port'],
            'method': data['method'],
        }
        
        event = Event(
            event_type=EventType.AUTH_SUCCESS.value,
            source=self.__class__.__name__,
            data=event_data,
            baseline_phase=self.state.get_current_phase().value
        )
        
        event.id = self.db.insert_event(event)
        
        self.publish_event(
            EventType.AUTH_SUCCESS.value,
            event_data,
            EventPriority.NORMAL
        )
        
        self.logger.info(f"SSH login: {data['user']} from {data['ip']}")
    
    def _handle_ssh_failure(self, data: Dict[str, str]):
        """Handle failed SSH login"""
        ip_address = data['ip']
        event_data = {
            'event': 'ssh_failure',
            'user': data['user'],
            'ip': ip_address,
            'port': data['port'],
            'method': data.get('method', 'unknown'),
        }

        event = Event(
            event_type=EventType.AUTH_FAILURE.value,
            source=self.__class__.__name__,
            data=event_data,
            baseline_phase=self.state.get_current_phase().value
        )

        event.id = self.db.insert_event(event)

        self.publish_event(
            EventType.AUTH_FAILURE.value,
            event_data,
            EventPriority.HIGH  # Failed auths are important
        )

        # Track failed auths for brute force detection
        self._track_failed_auth(ip_address)

        self.logger.warning(f"Failed SSH attempt: {data['user']} from {ip_address}")

        # Update threat intel
        from lonewarrior.storage.models import ThreatIntel
        threat = self.db.get_threat_intel(ip_address)
        if threat:
            threat.failed_auth_count += 1
            threat.reputation_score += self.config['threat_intel']['failed_auth_penalty']
            threat.reputation_score = min(100, threat.reputation_score)
        else:
            threat = ThreatIntel(
                ip_address=ip_address,
                failed_auth_count=1,
                reputation_score=self.config['threat_intel']['failed_auth_penalty']
            )

        self.db.upsert_threat_intel(threat)

    def _track_failed_auth(self, ip_address: str):
        """
        Track failed authentication attempts and detect brute force patterns.
        """
        from datetime import datetime, timezone
        import time

        now = time.time()

        # Initialize tracking for this IP if needed
        if ip_address not in self.failed_auth_tracking:
            self.failed_auth_tracking[ip_address] = []

        # Add this attempt
        self.failed_auth_tracking[ip_address].append(now)

        # Clean up old attempts (older than 5 minutes)
        self.failed_auth_tracking[ip_address] = [
            ts for ts in self.failed_auth_tracking[ip_address]
            if now - ts < 300
        ]

        # Detect brute force: more than 10 attempts in 1 minute
        recent_attempts = [
            ts for ts in self.failed_auth_tracking[ip_address]
            if now - ts < 60
        ]

        if len(recent_attempts) > 10:
            self.logger.warning(
                f"🚨 BRUTE FORCE DETECTED from {ip_address}: "
                f"{len(recent_attempts)} failed auths in last 60 seconds"
            )

            # Publish brute force event
            self.publish_event(
                'brute_force_detected',
                {
                    'ip': ip_address,
                    'attempts_1min': len(recent_attempts),
                    'attempts_5min': len(self.failed_auth_tracking[ip_address])
                },
                EventPriority.CRITICAL
            )
    
    def _handle_sudo(self, data: Dict[str, str]):
        """Handle sudo usage"""
        event_data = {
            'event': 'sudo',
            'user': data['user'],
            'target_user': data['target_user'],
            'command': data['command'],
        }
        
        event = Event(
            event_type='sudo_usage',
            source=self.__class__.__name__,
            data=event_data,
            baseline_phase=self.state.get_current_phase().value
        )
        
        self.db.insert_event(event)
        
        self.publish_event(
            'sudo_usage',
            event_data,
            EventPriority.NORMAL
        )
        
        self.logger.debug(f"Sudo: {data['user']} -> {data['target_user']}: {data['command']}")
