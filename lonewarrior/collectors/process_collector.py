"""
Process Collector - Monitors running processes
"""

import os
import psutil
from typing import Dict, Any, List, Set
from datetime import datetime
import re

from lonewarrior.collectors.base import BaseCollector
from lonewarrior.storage.models import Event, EventType
from lonewarrior.core.event_bus import EventPriority


class ProcessCollector(BaseCollector):
    """Collects process information and tracks lineage"""

    # Cleanup interval (every N collections)
    CLEANUP_INTERVAL = 100
    # Maximum cache size before forced cleanup
    MAX_CACHE_SIZE = 10000

    # Suspicious command patterns
    SUSPICIOUS_PATTERNS = {
        r'(/etc/passwd|/etc/shadow)': 'Credential access attempt',
        r'(wget|curl|nc|netcat|ncat).*\s+(http|ftp)': 'Remote download tool',
        r'(base64|python.*-c|bash.*-c).*":': 'Obfuscated command execution',
        r'(chmod|chown).*\+x.*(/tmp|/var/tmp)': 'Malicious executable creation',
        r'ssh.*-i.*(/tmp|/dev/shm|/var/tmp)': 'Potential backdoor activation',
        r'(iptables|ufw).*--flush': 'Firewall tampering',
        r'(rm|del).*-rf\s+/': 'Destructive command',
        r':\(/bin/sh|/bin/bash)\s': 'Shell injection attempt',
        r'(/\.ssh|/\.config|/\.local).*\.(txt|sh|py|php)': 'Potential persistence',
    }

    # Legitimate parent processes that spawning suspicious children is concerning
    LEGITIMATE_PARENTS = {
        'apache2', 'nginx', 'httpd', 'mysqld', 'postgres', 'sshd',
        'systemd', 'cron', 'bash', 'sh', 'python3', 'python'
    }

    # Suspicious parent processes
    SUSPICIOUS_PARENTS = {
        'tmp', 'unknown', 'www-data', 'nobody'
    }

    # High-risk process names
    HIGH_RISK_PROCESSES = {
        'msfconsole', 'metasploit', 'meterpreter',
        'nc', 'netcat', 'ncat',
        'socat',
        'hydra', 'john', 'hashcat',
        'nmap', 'masscan', 'zmap',
        'sqlmap',
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen_pids: Set[int] = set()
        self.process_cache: Dict[int, Dict[str, Any]] = {}
        self._collection_count = 0
    
    def _get_collection_interval(self) -> int:
        return self.config['collection']['process_interval']

    def _cleanup_stale_entries(self):
        """Periodic cleanup to prevent memory leaks from stale PIDs.

        Removes entries from seen_pids and process_cache that no longer
        correspond to running processes. This handles edge cases where
        the normal cleanup in collect() might miss terminated processes.
        """
        try:
            # Get current running PIDs
            current_pids = {p.pid for p in psutil.process_iter(['pid'])}

            # Find stale entries
            stale_pids = self.seen_pids - current_pids
            if stale_pids:
                self.logger.debug(f"Cleaning up {len(stale_pids)} stale PID entries")
                for pid in stale_pids:
                    self.seen_pids.discard(pid)
                    self.process_cache.pop(pid, None)

            # Also clean cache entries not in seen_pids (shouldn't happen, but defensive)
            cache_only = set(self.process_cache.keys()) - self.seen_pids
            for pid in cache_only:
                self.process_cache.pop(pid, None)

        except Exception as e:
            self.logger.warning(f"Error during stale PID cleanup: {e}")

    def collect(self):
        """Collect current process information"""
        # Periodic cleanup to prevent memory leaks
        self._collection_count += 1
        if (self._collection_count % self.CLEANUP_INTERVAL == 0 or
                len(self.process_cache) > self.MAX_CACHE_SIZE):
            self._cleanup_stale_entries()

        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'ppid', 'create_time']):
            try:
                info = proc.info
                pid = info['pid']
                current_pids.add(pid)
                
                # New process detected
                if pid not in self.seen_pids:
                    self._handle_new_process(proc, info)
                    self.seen_pids.add(pid)
                
                # Update cache
                self.process_cache[pid] = info
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Detect terminated processes
        terminated = self.seen_pids - current_pids
        for pid in terminated:
            self._handle_terminated_process(pid)
            self.seen_pids.discard(pid)
            self.process_cache.pop(pid, None)
    
    def _handle_new_process(self, proc: psutil.Process, info: Dict[str, Any]):
        """Handle new process detection"""
        pid = info['pid']
        name = info['name']
        username = info['username']
        cmdline = ' '.join(info['cmdline']) if info['cmdline'] else ''
        ppid = info['ppid']

        # Get parent info
        parent_name = None
        parent_cmdline = None
        if ppid and ppid in self.process_cache:
            parent_info = self.process_cache[ppid]
            parent_name = parent_info['name']
            parent_cmdline = ' '.join(parent_info['cmdline']) if parent_info['cmdline'] else ''

        # Enhanced lineage analysis
        lineage_risk = self._analyze_lineage_risk(
            name,
            parent_name or '',
            parent_cmdline or '',
            username
        )

        # Publish event
        event_data = {
            'pid': pid,
            'name': name,
            'username': username,
            'cmdline': cmdline,
            'ppid': ppid,
            'parent_name': parent_name,
            'parent_cmdline': parent_cmdline,
            'create_time': info['create_time'],
            'lineage_risk': lineage_risk,
        }

        # Create event
        event = Event(
            event_type=EventType.PROCESS_NEW.value,
            source=self.__class__.__name__,
            data=event_data,
            baseline_phase=self.state.get_current_phase().value
        )

        # Save to database
        event.id = self.db.insert_event(event)

        # Publish to event bus
        priority = EventPriority.HIGH if lineage_risk > 0 else EventPriority.NORMAL
        self.publish_event(
            EventType.PROCESS_NEW.value,
            event_data,
            priority
        )

        if lineage_risk > 0:
            self.logger.warning(f"[LINEAGE_RISK] Process {name} (PID {pid}) - {lineage_risk}")
        else:
            self.logger.debug(f"New process: {name} (PID {pid}) by {username}, parent: {parent_name}")

    def _analyze_lineage_risk(self, name: str, parent_name: str, parent_cmdline: str, username: str) -> int:
        """
        Analyze process lineage for suspicious patterns.

        Returns risk score (0-10) based on lineage characteristics.
        Higher score means more suspicious.
        """
        risk_score = 0

        # Check 1: Legitimate parent spawning suspicious tool
        if parent_name in self.LEGITIMATE_PARENTS and name in self.HIGH_RISK_PROCESSES:
            risk_score += 5
            self.logger.warning(f"Lineage risk: {parent_name} spawning {name}")

        # Check 2: Suspicious parent spawning any process
        if parent_name in self.SUSPICIOUS_PARENTS:
            risk_score += 4

        # Check 3: No parent detected
        if not parent_name:
            risk_score += 3  # Orphaned process or parent already dead

        # Check 4: Parent is in /tmp or suspicious location
        if parent_cmdline and '/tmp/' in parent_cmdline:
            risk_score += 3

        # Check 5: Web server spawning shell
        if parent_name in ['apache2', 'nginx', 'httpd'] and name in ['bash', 'sh', 'python', 'perl', 'nc']:
            risk_score += 6  # High risk - likely webshell or RCE

        # Check 6: High-risk tool spawned by unexpected parent
        if name in self.HIGH_RISK_PROCESSES and parent_name not in self.LEGITIMATE_PARENTS:
            risk_score += 4

        # Check 7: Check for suspicious command patterns in parent
        for pattern, desc in self.SUSPICIOUS_PATTERNS.items():
            if parent_cmdline and re.search(pattern, parent_cmdline):
                risk_score += 3
                break

        return min(risk_score, 10)  # Cap at 10
    
    def _handle_terminated_process(self, pid: int):
        """Handle process termination"""
        if pid in self.process_cache:
            info = self.process_cache[pid]
            
            event_data = {
                'pid': pid,
                'name': info['name'],
                'username': info['username'],
            }
            
            event = Event(
                event_type=EventType.PROCESS_TERMINATED.value,
                source=self.__class__.__name__,
                data=event_data,
                baseline_phase=self.state.get_current_phase().value
            )
            
            self.db.insert_event(event)
            
            self.publish_event(
                EventType.PROCESS_TERMINATED.value,
                event_data,
                EventPriority.LOW
            )
