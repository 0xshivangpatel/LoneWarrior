"""
Web Log Collector - Tails nginx/apache access logs and publishes suspicious request events.

Targets SMBs running web apps on a VPS with nginx or apache.
Parses combined log format and emits ``web_request`` events for every line that
contains a potentially malicious pattern so the WebLogAnalyzer can score them.
"""

import logging
import os
import re
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import unquote_plus

from lonewarrior.collectors.base import BaseCollector
from lonewarrior.core.event_bus import EventPriority


logger = logging.getLogger(__name__)


# Combined log format regex -------------------------------------------------
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
COMBINED_LOG_RE = re.compile(
    r'(?P<remote_addr>\S+)'           # 1  remote_addr
    r' - '
    r'(?P<remote_user>\S+)'           # 2  remote_user
    r' \[(?P<time_local>[^\]]+)\]'    # 3  time_local
    r' "(?P<request>[^"]*)"'          # 4  request line
    r' (?P<status>\d{3})'             # 5  status code
    r' (?P<body_bytes_sent>\S+)'      # 6  body_bytes_sent
    r' "(?P<http_referer>[^"]*)"'     # 7  referer
    r' "(?P<http_user_agent>[^"]*)"'  # 8  user-agent
)

# Quick pre-filter: if a line matches *any* of these, it is worth publishing.
# Kept intentionally broad so the analyzer can do the precise classification.
_SUSPICIOUS_HINTS = re.compile(
    r'(?i)'
    r'(?:union\s+select|or\s+1\s*=\s*1|drop\s+table|;\s*select|sleep\s*\(|benchmark\s*\(|--)'
    r'|(?:<script|javascript:|onerror\s*=|onload\s*=|eval\s*\(|document\.cookie|alert\s*\()'
    r'|(?:%3[Cc]script|%3[Cc]%2[Ff]script)'
    r'|(?:\.\./|\.\.%2[Ff]|/etc/passwd|/etc/shadow|/proc/self|php://)'
    r'|(?:=https?://|=ftp://)'
    r'|(?:;\s*ls|;\s*cat|\|\s*cat|\$\(|`|&&\s*wget|\|\s*curl|;\s*rm|;\s*bash|\|/bin/sh)'
    r'|(?:sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|nuclei)'
)

# Default log file search paths
DEFAULT_LOG_PATHS: List[str] = [
    '/var/log/nginx/access.log',
    '/var/log/apache2/access.log',
    '/var/log/httpd/access_log',
]


class WebLogCollector(BaseCollector):
    """
    Tails web-server access logs (nginx / apache combined format) and
    publishes ``web_request`` events for lines that look suspicious.
    """

    def __init__(self, config: Dict[str, Any], database, event_bus, state_manager):
        super().__init__(config, database, event_bus, state_manager)

        # Resolve the log file path -------------------------------------------
        self.log_path: Optional[str] = self._resolve_log_path()
        if self.log_path:
            self.logger.info(f"Monitoring web access log: {self.log_path}")
        else:
            self.logger.warning(
                "No web access log found. Set 'weblog.log_path' in config "
                "or ensure nginx/apache logs exist in default locations."
            )

        # File tracking state --------------------------------------------------
        self._file_handle = None
        self._inode: Optional[int] = None   # Detect log rotation
        self._seeked = False                 # True once we have seeked to end on first run

    # -- BaseCollector interface ------------------------------------------------

    def _get_collection_interval(self) -> int:
        return self.config.get('weblog', {}).get('collection_interval', 5)

    def collect(self):
        """Read new lines from the access log and publish suspicious ones."""
        if not self.log_path:
            return

        # Open / reopen the file as needed (handles rotation).
        if not self._ensure_file_open():
            return

        lines = self._read_new_lines()
        for line in lines:
            parsed = self._parse_line(line)
            if parsed is None:
                continue

            # Only publish events that look suspicious (quick regex pre-filter).
            # URL-decode first — attackers routinely use +, %20, %27, %3C etc.
            # Double-decode catches double-encoding evasion (%2527 -> %27 -> ').
            combined_raw = (
                f"{parsed.get('request', '')} "
                f"{parsed.get('referer', '')} "
                f"{parsed.get('user_agent', '')}"
            )
            decoded_once = unquote_plus(combined_raw)
            combined_text = unquote_plus(decoded_once)
            status_code = parsed.get('status', 0)

            is_suspicious = bool(_SUSPICIOUS_HINTS.search(combined_text))
            is_404_burst_candidate = (status_code == 404)
            is_post = parsed.get('method', '').upper() == 'POST'

            if is_suspicious or is_404_burst_candidate or is_post:
                self.publish_event(
                    'web_request',
                    parsed,
                    EventPriority.NORMAL,
                )

    def start(self):
        """Start collector thread."""
        super().start()

    def stop(self):
        """Stop collector and close file handle."""
        super().stop()
        self._close_file()

    # -- Internal helpers -------------------------------------------------------

    def _resolve_log_path(self) -> Optional[str]:
        """Return the path to the access log, respecting user config."""
        # User override via config
        user_path = self.config.get('weblog', {}).get('log_path')
        if user_path and os.path.isfile(user_path):
            return user_path

        # Auto-detect from well-known locations
        for path in DEFAULT_LOG_PATHS:
            if os.path.isfile(path):
                return path

        return None

    def _ensure_file_open(self) -> bool:
        """
        Make sure we have a valid file handle.  Handles first-open and
        log-rotation (inode change).
        Returns True when the handle is ready to read.
        """
        try:
            stat = os.stat(self.log_path)
        except FileNotFoundError:
            self._close_file()
            return False

        current_inode = stat.st_ino

        # Detect rotation: inode changed or file got smaller
        if self._file_handle is not None and current_inode != self._inode:
            self.logger.info("Log file rotated, reopening")
            self._close_file()

        if self._file_handle is None:
            try:
                self._file_handle = open(self.log_path, 'r', encoding='utf-8', errors='replace')
                self._inode = current_inode

                # On the very first open, seek to end so we only process new lines.
                if not self._seeked:
                    self._file_handle.seek(0, os.SEEK_END)
                    self._seeked = True
                    self.logger.info("Seeked to end of log file for initial tail")
            except (PermissionError, OSError) as exc:
                self.logger.warning(f"Cannot open log file: {exc}")
                return False

        return True

    def _read_new_lines(self) -> List[str]:
        """Read all new complete lines from the current file handle."""
        lines: List[str] = []
        try:
            for line in self._file_handle:
                stripped = line.rstrip('\n\r')
                if stripped:
                    lines.append(stripped)
        except (IOError, OSError) as exc:
            self.logger.warning(f"Error reading log file: {exc}")
            self._close_file()
        return lines

    def _close_file(self):
        if self._file_handle is not None:
            try:
                self._file_handle.close()
            except OSError:
                pass
            self._file_handle = None
            self._inode = None

    @staticmethod
    def _parse_line(line: str) -> Optional[Dict[str, Any]]:
        """Parse a single combined-format log line into a dict."""
        match = COMBINED_LOG_RE.match(line)
        if not match:
            return None

        data = match.groupdict()

        # Decompose the request line: "METHOD /path HTTP/x.x"
        request = data.get('request', '')
        parts = request.split(' ', 2)
        method = parts[0] if len(parts) >= 1 else ''
        url = parts[1] if len(parts) >= 2 else request
        protocol = parts[2] if len(parts) >= 3 else ''

        # Parse the timestamp
        time_str = data.get('time_local', '')
        try:
            timestamp = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
        except (ValueError, TypeError):
            timestamp = datetime.utcnow()

        status = int(data.get('status', 0))
        try:
            body_bytes = int(data.get('body_bytes_sent', 0))
        except (ValueError, TypeError):
            body_bytes = 0

        return {
            'source_ip': data['remote_addr'],
            'remote_user': data['remote_user'],
            'timestamp': timestamp.isoformat(),
            'method': method,
            'url': url,
            'protocol': protocol,
            'request': request,
            'status': status,
            'body_bytes_sent': body_bytes,
            'referer': data['http_referer'],
            'user_agent': data['http_user_agent'],
            'raw_line': line,
        }
