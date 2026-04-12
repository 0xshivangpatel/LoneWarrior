"""
Web Log Analyzer - Detects OWASP attack patterns from web_request events.

Subscribes to ``web_request`` events emitted by WebLogCollector and applies
regex-based detection rules for SQL injection, XSS, path traversal, RFI,
command injection, scanner/bot activity, and brute-force login attempts.

Each positive hit produces a Detection record in the database and publishes a
``detection_created`` event so the ConfidenceScorer (and ActionExecutor) can
react accordingly.
"""

import logging
import re
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from urllib.parse import unquote_plus

from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, DetectionType
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# 1. SQL Injection
_SQLI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)union\s+(all\s+)?select'), 'UNION SELECT'),
    (re.compile(r"(?i)(?:^|\s|'|\")or\s+1\s*=\s*1"), 'OR 1=1'),
    (re.compile(r"(?i)'\s*or\s*'"), "' OR '"),
    (re.compile(r'--\s'), 'SQL comment (--)'),
    (re.compile(r'(?i)drop\s+table'), 'DROP TABLE'),
    (re.compile(r'(?i);\s*select\s'), '; SELECT'),
    (re.compile(r'(?i)sleep\s*\('), 'SLEEP('),
    (re.compile(r'(?i)benchmark\s*\('), 'BENCHMARK('),
    (re.compile(r'(?i)(?:and|or)\s+\d+=\d+'), 'Boolean-based SQLi'),
    (re.compile(r"(?i)'\s*;\s*--"), "Quote-semicolon-comment"),
]

# 2. XSS (Cross-Site Scripting)
_XSS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)<\s*script'), '<script>'),
    (re.compile(r'(?i)javascript\s*:'), 'javascript:'),
    (re.compile(r'(?i)onerror\s*='), 'onerror='),
    (re.compile(r'(?i)onload\s*='), 'onload='),
    (re.compile(r'(?i)eval\s*\('), 'eval('),
    (re.compile(r'(?i)document\.cookie'), 'document.cookie'),
    (re.compile(r'(?i)alert\s*\('), 'alert('),
    (re.compile(r'(?i)%3[Cc]\s*script'), '%3Cscript (URL-encoded)'),
    (re.compile(r'(?i)%3[Cc]%2[Ff]script'), '%3C%2Fscript (URL-encoded)'),
    (re.compile(r'(?i)on(?:mouse(?:over|out)|focus|blur|click)\s*='), 'DOM event handler'),
]

# 3. Path Traversal / LFI
_LFI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?:^|[/\\])\.\.(?:[/\\]|%2[Ff])'), '../ traversal'),
    (re.compile(r'(?i)\.\.%2[Ff]'), '..%2f (URL-encoded traversal)'),
    (re.compile(r'/etc/passwd'), '/etc/passwd'),
    (re.compile(r'/etc/shadow'), '/etc/shadow'),
    (re.compile(r'/proc/self'), '/proc/self'),
    (re.compile(r'(?i)\.{4}//'), '....// traversal'),
    (re.compile(r'(?i)php://filter'), 'php://filter'),
    (re.compile(r'(?i)php://input'), 'php://input'),
]

# 4. Remote File Inclusion (RFI)
_RFI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'=https?://'), '=http(s):// in query param'),
    (re.compile(r'=ftp://'), '=ftp:// in query param'),
]

# 5. Command Injection
_CMDI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r';\s*ls\b'), '; ls'),
    (re.compile(r'\|\s*cat\b'), '| cat'),
    (re.compile(r'\$\('), '$('),
    (re.compile(r'`'), 'backtick'),
    (re.compile(r'&&\s*wget\b'), '&& wget'),
    (re.compile(r'\|\s*curl\b'), '| curl'),
    (re.compile(r';\s*rm\b'), '; rm'),
    (re.compile(r';\s*bash\b'), '; bash'),
    (re.compile(r'\|/bin/sh'), '|/bin/sh'),
    (re.compile(r';\s*/bin/'), '; /bin/...'),
]

# 6. Scanner / bot user-agents (case-insensitive substring match)
_SCANNER_UA_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)\bsqlmap\b'), 'sqlmap'),
    (re.compile(r'(?i)\bnikto\b'), 'nikto'),
    (re.compile(r'(?i)\bnmap\b'), 'nmap'),
    (re.compile(r'(?i)\bmasscan\b'), 'masscan'),
    (re.compile(r'(?i)\bdirbuster\b'), 'dirbuster'),
    (re.compile(r'(?i)\bgobuster\b'), 'gobuster'),
    (re.compile(r'(?i)\bwfuzz\b'), 'wfuzz'),
    (re.compile(r'(?i)\bnuclei\b'), 'nuclei'),
]

# Login-like URL fragments (case-insensitive)
_LOGIN_URL_RE = re.compile(
    r'(?i)(?:/login|/signin|/auth|/session|/wp-login|/admin/login|/user/login|/account/login)'
)

# Rate-based thresholds
_404_THRESHOLD = 20          # hits per IP within the window
_404_WINDOW_SECONDS = 60
_POST_THRESHOLD = 15         # rapid POSTs to login-like URLs
_POST_WINDOW_SECONDS = 60
_CLEANUP_INTERVAL = 300      # 5 minutes


class WebLogAnalyzer:
    """
    Subscribes to ``web_request`` events and detects OWASP attack patterns.

    For each positive detection it:
      1. Inserts a ``Detection`` record into the database.
      2. Publishes a ``detection_created`` event so the ConfidenceScorer
         (and ActionExecutor) can react.
    """

    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager

        # Rate-based tracking -------------------------------------------------
        # {ip: [timestamp_float, ...]}
        self._404_tracker: Dict[str, List[float]] = defaultdict(list)
        self._post_login_tracker: Dict[str, List[float]] = defaultdict(list)

        # Cleanup bookkeeping
        self._last_cleanup: float = time.time()

        # Background cleanup thread -------------------------------------------
        self._running = False
        self._cleanup_thread = None

        # Subscribe to web_request events
        self.event_bus.subscribe('web_request', self._handle_web_request)

    # -- lifecycle -------------------------------------------------------------

    def start(self):
        """Start the analyzer (including periodic cleanup thread)."""
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        self._cleanup_thread.start()
        logger.info("WebLogAnalyzer started")

    def stop(self):
        """Stop the analyzer."""
        self._running = False
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=10)
        logger.info("WebLogAnalyzer stopped")

    # -- event handler ---------------------------------------------------------

    def _handle_web_request(self, event: InternalEvent):
        """Dispatch a single web_request event through all detection rules."""
        data = event.data
        source_ip = data.get('source_ip', '')
        url = data.get('url', '')
        request = data.get('request', '')
        referer = data.get('referer', '') or ''
        user_agent = data.get('user_agent', '') or ''
        status = data.get('status', 0)
        method = (data.get('method', '') or '').upper()

        # Combine fields that should all be tested for injection patterns.
        # URL-decode to catch encoded attacks (+, %20, %27, %3C, double-encoding).
        raw_inspectable = f"{request} {referer} {user_agent}"
        decoded_once = unquote_plus(raw_inspectable)
        inspectable = unquote_plus(decoded_once)

        now = time.time()

        # 1. SQL Injection
        self._check_patterns(
            inspectable, _SQLI_PATTERNS,
            attack_type='SQL Injection',
            min_confidence=70.0, max_confidence=85.0,
            source_ip=source_ip, data=data,
        )

        # 2. XSS
        self._check_patterns(
            inspectable, _XSS_PATTERNS,
            attack_type='XSS',
            min_confidence=60.0, max_confidence=75.0,
            source_ip=source_ip, data=data,
        )

        # 3. Path Traversal / LFI
        self._check_patterns(
            inspectable, _LFI_PATTERNS,
            attack_type='Path Traversal / LFI',
            min_confidence=75.0, max_confidence=85.0,
            source_ip=source_ip, data=data,
        )

        # 4. Remote File Inclusion
        # Only check the URL and referer (query-param context), decoded
        rfi_text = unquote_plus(unquote_plus(f"{url} {referer}"))
        self._check_patterns(
            rfi_text, _RFI_PATTERNS,
            attack_type='Remote File Inclusion',
            min_confidence=80.0, max_confidence=80.0,
            source_ip=source_ip, data=data,
        )

        # 5. Command Injection
        self._check_patterns(
            inspectable, _CMDI_PATTERNS,
            attack_type='Command Injection',
            min_confidence=80.0, max_confidence=90.0,
            source_ip=source_ip, data=data,
        )

        # 6. Scanner / bot detection (user-agent)
        self._check_patterns(
            user_agent, _SCANNER_UA_PATTERNS,
            attack_type='Scanner/Bot Detected',
            min_confidence=40.0, max_confidence=60.0,
            source_ip=source_ip, data=data,
        )

        # 6b. Rapid-404 scanner detection (rate-based)
        if status == 404:
            self._404_tracker[source_ip].append(now)
            recent = [
                ts for ts in self._404_tracker[source_ip]
                if now - ts <= _404_WINDOW_SECONDS
            ]
            self._404_tracker[source_ip] = recent
            if len(recent) >= _404_THRESHOLD:
                self._create_detection(
                    attack_type='Scanner/Bot Detected (rapid 404s)',
                    confidence=55.0,
                    matched_pattern=f'{len(recent)} 404s in {_404_WINDOW_SECONDS}s',
                    source_ip=source_ip,
                    data=data,
                )
                # Reset to avoid duplicate detections every single request
                self._404_tracker[source_ip] = []

        # 7. Brute-force on web login (rate-based)
        if method == 'POST' and _LOGIN_URL_RE.search(url):
            self._post_login_tracker[source_ip].append(now)
            recent = [
                ts for ts in self._post_login_tracker[source_ip]
                if now - ts <= _POST_WINDOW_SECONDS
            ]
            self._post_login_tracker[source_ip] = recent
            if len(recent) >= _POST_THRESHOLD:
                self._create_detection(
                    attack_type='Web Login Brute Force',
                    confidence=60.0,
                    matched_pattern=f'{len(recent)} POSTs to {url} in {_POST_WINDOW_SECONDS}s',
                    source_ip=source_ip,
                    data=data,
                )
                self._post_login_tracker[source_ip] = []

    # -- pattern matching helper -----------------------------------------------

    def _check_patterns(
        self,
        text: str,
        patterns: List[Tuple[re.Pattern, str]],
        attack_type: str,
        min_confidence: float,
        max_confidence: float,
        source_ip: str,
        data: Dict[str, Any],
    ):
        """
        Test *text* against a list of regex patterns.  On the first hit,
        create a detection and return (one detection per attack category per
        request is enough).
        """
        for regex, label in patterns:
            if regex.search(text):
                # Scale confidence within the given range based on how
                # "specific" the matched pattern is (position in the list
                # roughly correlates with specificity, so just use the
                # midpoint for a single-hit and max for multi-hit).
                confidence = (min_confidence + max_confidence) / 2.0
                self._create_detection(
                    attack_type=attack_type,
                    confidence=confidence,
                    matched_pattern=label,
                    source_ip=source_ip,
                    data=data,
                )
                return  # one detection per category per request

    # -- detection creation ----------------------------------------------------

    def _create_detection(
        self,
        attack_type: str,
        confidence: float,
        matched_pattern: str,
        source_ip: str,
        data: Dict[str, Any],
    ):
        """Build a Detection, persist it, and publish the event."""
        url = data.get('url', '')
        user_agent = data.get('user_agent', '')

        description = (
            f"{attack_type} from {source_ip}: "
            f"matched '{matched_pattern}' in request to {url}"
        )

        detection_data = {
            'attack_type': attack_type,
            'matched_pattern': matched_pattern,
            'source_ip': source_ip,
            'url': url,
            'method': data.get('method', ''),
            'user_agent': user_agent,
            'referer': data.get('referer', ''),
            'status': data.get('status', 0),
            'raw_line': data.get('raw_line', ''),
        }

        detection = Detection(
            detection_type=DetectionType.BASELINE_DEVIATION.value,
            description=description,
            confidence_score=confidence,
            data=detection_data,
        )

        detection.id = self.db.insert_detection(detection)

        logger.warning(
            f"WEBLOG DETECTION [{attack_type}] confidence={confidence:.0f} "
            f"ip={source_ip} pattern='{matched_pattern}' url={url}"
        )

        # Publish so ConfidenceScorer and ActionExecutor can act.
        self.event_bus.publish(
            'detection_created',
            {
                'detection_id': detection.id,
                'type': detection.detection_type,
                'description': description,
                'confidence': confidence,
                'source_ip': source_ip,
                'attack_type': attack_type,
            },
            EventPriority.HIGH,
            'WebLogAnalyzer',
        )

    # -- periodic cleanup of rate-tracking dicts --------------------------------

    def _cleanup_loop(self):
        """Background thread that prunes stale entries from rate trackers."""
        while self._running:
            time.sleep(30)  # check every 30 seconds
            self._prune_trackers()

    def _prune_trackers(self):
        """Remove entries older than 5 minutes from rate-tracking dicts."""
        cutoff = time.time() - _CLEANUP_INTERVAL
        for tracker in (self._404_tracker, self._post_login_tracker):
            stale_keys = []
            for ip, timestamps in tracker.items():
                fresh = [ts for ts in timestamps if ts > cutoff]
                if fresh:
                    tracker[ip] = fresh
                else:
                    stale_keys.append(ip)
            for ip in stale_keys:
                del tracker[ip]
