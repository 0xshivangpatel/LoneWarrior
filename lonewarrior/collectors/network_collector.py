"""
Network Collector - Monitors network connections
"""

import psutil
import socket
from typing import Dict, Any, Set, Tuple, List
from collections import defaultdict
from datetime import datetime, timedelta

from lonewarrior.collectors.base import BaseCollector
from lonewarrior.storage.models import Event, EventType
from lonewarrior.core.event_bus import EventPriority


class NetworkCollector(BaseCollector):
    """Collects network connection information"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen_connections: Set[Tuple[str, int, str, int]] = set()

        # Track for scanning detection - improved
        self.connection_history: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)  # ip -> [(timestamp, port)]
        self.port_access_history: Dict[int, List[datetime]] = defaultdict(list)
        self.connection_attempts: Dict[Tuple[str, str, int], List[datetime]] = defaultdict(list)  # (local_addr, remote_addr, remote_port) -> timestamps

        # Detection thresholds - made more sensitive
        self.port_scan_threshold = 10  # Reduced from 20: ports accessed in < 30 seconds
        self.rapid_connection_threshold = 20  # Reduced from 30: connections in < 60 seconds
        self.failed_connection_threshold = 15  # Failed connections from same IP in < 30 seconds

        # Track failed connections
        self.failed_connections: Dict[str, List[datetime]] = defaultdict(list)  # remote_addr -> timestamps
    
    def _get_collection_interval(self) -> int:
        return self.config['collection']['network_interval']
    
    def collect(self):
        """Collect current network connections"""
        current_connections = set()

        try:
            connections = psutil.net_connections(kind='inet')
        except (PermissionError, psutil.AccessDenied):
            self.logger.warning("Insufficient permissions for network monitoring")
            return

        for conn in connections:
            try:
                if not conn.raddr:
                    continue

                local_addr = conn.laddr.ip if conn.laddr else ''
                local_port = conn.laddr.port if conn.laddr else 0
                remote_addr = conn.raddr.ip if conn.raddr else ''
                remote_port = conn.raddr.port if conn.raddr else 0

                conn_tuple = (local_addr, local_port, remote_addr, remote_port)
                current_connections.add(conn_tuple)

                # Track all connections, not just established
                self._track_all_connections(conn, conn_tuple)

                # Track ESTABLISHED connections for baseline learning
                if conn.status == 'ESTABLISHED':
                    # New established connection
                    if conn_tuple not in self.seen_connections:
                        self._handle_new_connection(conn)
                        self.seen_connections.add(conn_tuple)

                        # Track connection history for scanning detection
                        self._track_connection(remote_addr, remote_port)

            except:
                continue

        # Cleanup old connections
        closed = self.seen_connections - current_connections
        self.seen_connections = current_connections

        # Periodically check for scanning patterns
        self._detect_scanning_patterns()
    
    def _handle_new_connection(self, conn):
        """Handle new network connection"""
        local_addr = conn.laddr.ip if conn.laddr else ''
        local_port = conn.laddr.port if conn.laddr else 0
        remote_addr = conn.raddr.ip if conn.raddr else ''
        remote_port = conn.raddr.port if conn.raddr else 0
        
        # Get process info if available
        pid = conn.pid
        process_name = None
        process_user = None
        
        if pid:
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()
                process_user = proc.username()
            except (psutil.NoSuchProcess, psutil.AccessDenied):

                pass
        
        event_data = {
            'local_addr': local_addr,
            'local_port': local_port,
            'remote_addr': remote_addr,
            'remote_port': remote_port,
            'pid': pid,
            'process_name': process_name,
            'process_user': process_user,
            'status': conn.status,
        }
        
        event = Event(
            event_type=EventType.NETWORK_CONNECTION.value,
            source=self.__class__.__name__,
            data=event_data,
            baseline_phase=self.state.get_current_phase().value
        )
        
        event.id = self.db.insert_event(event)
        
        # Publish event
        self.publish_event(
            EventType.NETWORK_CONNECTION.value,
            event_data,
            EventPriority.NORMAL
        )
        
        self.logger.debug(f"New connection: {process_name or 'unknown'} -> {remote_addr}:{remote_port}")

    def _track_all_connections(self, conn, conn_tuple: Tuple[str, int, str, int]):
        """
        Track all connections including non-established for port scan detection.
        """
        now = datetime.now()
        local_addr = conn_tuple[0]
        remote_addr = conn_tuple[2]
        remote_port = conn_tuple[3]

        # Track all connection attempts
        attempt_key = (local_addr, remote_addr, remote_port)
        self.connection_attempts[attempt_key].append(now)

        # Clean up old connection attempts
        cutoff = now - timedelta(minutes=5)
        self.connection_attempts[attempt_key] = [
            ts for ts in self.connection_attempts[attempt_key] if ts > cutoff
        ]

    def _track_connection(self, remote_addr: str, remote_port: int):
        """
        Track connection history for scanning detection.
        """
        now = datetime.now()

        # Track connection per IP
        self.connection_history[remote_addr].append((now, remote_port))
        # Track port access
        self.port_access_history[remote_port].append(now)

        # Clean up old entries (older than 5 minutes)
        cutoff = now - timedelta(minutes=5)
        self.connection_history[remote_addr] = [
            (ts, port) for ts, port in self.connection_history[remote_addr] if ts > cutoff
        ]
        self.port_access_history[remote_port] = [
            ts for ts in self.port_access_history[remote_port] if ts > cutoff
        ]

    def _detect_scanning_patterns(self):
        """
        Detect port scanning and rapid connection patterns.
        """
        now = datetime.now()
        recent_cutoff = now - timedelta(seconds=30)

        # Check for port scanning: many different ports accessed in short time
        for ip, connections in list(self.connection_history.items()):
            recent_connections = [(ts, port) for ts, port in connections if ts > recent_cutoff]

            if len(recent_connections) >= 5:
                # Count unique ports this IP connected to recently
                unique_ports = set([port for ts, port in recent_connections])

                if len(unique_ports) >= self.port_scan_threshold:
                    self.logger.warning(
                        f"🚨 PORT SCAN DETECTED from {ip}: "
                        f"{len(unique_ports)} unique ports in last 30 seconds"
                    )

                    # Publish port scan event
                    self.publish_event(
                        'port_scan_detected',
                        {
                            'source_ip': ip,
                            'unique_ports': len(unique_ports),
                            'connections': len(recent_connections),
                            'time_window': '30s'
                        },
                        EventPriority.HIGH
                    )

        # Check for rapid connection attempts (possible DoS)
        for ip, connections in list(self.connection_history.items()):
            rapid_cutoff = now - timedelta(seconds=60)
            rapid_connections = [(ts, port) for ts, port in connections if ts > rapid_cutoff]

            if len(rapid_connections) >= self.rapid_connection_threshold:
                self.logger.warning(
                    f"🚨 RAPID CONNECTIONS from {ip}: "
                    f"{len(rapid_connections)} connections in last 60 seconds"
                )

                # Publish rapid connection event
                self.publish_event(
                    'rapid_connections_detected',
                    {
                        'source_ip': ip,
                        'connection_count': len(rapid_connections),
                        'time_window': '60s'
                    },
                    EventPriority.HIGH
                )