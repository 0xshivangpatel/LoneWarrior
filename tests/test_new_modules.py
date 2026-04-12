"""
End-to-end tests for the three new modules:
  1. HardeningAuditor  (server hardening checks)
  2. WebLogCollector + WebLogAnalyzer  (OWASP attack detection from web logs)
  3. AlertManager  (email + webhook notifications)

Tests verify the modules work individually and integrate correctly through
the EventBus pipeline.
"""

import json
import os
import sys
import tempfile
import textwrap
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from lonewarrior.core.event_bus import EventBus, EventPriority, InternalEvent
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, DetectionType


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_data_dir(tmp_path):
    """Temporary data directory with a fresh database."""
    data_dir = tmp_path / "lw_test"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def db(tmp_data_dir):
    """Fresh database instance."""
    return Database(str(tmp_data_dir / "test.db"))


@pytest.fixture
def event_bus():
    """Started event bus, stopped after test."""
    bus = EventBus()
    bus.start()
    yield bus
    bus.stop()


@pytest.fixture
def base_config(tmp_data_dir):
    """Minimal config dict that satisfies all modules."""
    return {
        "general": {
            "data_dir": str(tmp_data_dir),
            "log_dir": str(tmp_data_dir / "logs"),
            "log_level": "DEBUG",
        },
        "baseline": {
            "phase0_duration": 300,
            "phase1_min_duration": 1800,
            "phase1_max_duration": 2700,
            "phase1_min_events": 200,
            "phase2_min_duration": 7200,
            "phase2_max_duration": 10800,
            "phase2_variability_threshold": 0.3,
            "freeze_on_attack": True,
            "freeze_cooldown": 1800,
            "update_confirmation_count": 3,
        },
        "collection": {
            "process_interval": 10,
            "network_interval": 15,
            "auth_log_interval": 30,
            "file_integrity_interval": 60,
            "service_interval": 60,
            "container_interval": 30,
        },
        "confidence": {
            "contain": 25,
            "aggressive": 50,
            "lockdown": 75,
            "observe": 0,
            "weight_invariant": 50,
            "weight_deviation": 20,
            "weight_fim": 30,
            "weight_lineage": 25,
            "weight_killchain": 40,
            "weight_integration": 15,
        },
        "actions": {"enabled": True, "ip_block": {"enabled": True, "default_ttl": 60}},
        "containment": {"auto_enable": True, "trigger_threshold": 60},
        "weblog": {
            "enabled": True,
            "log_path": "",
            "collection_interval": 1,
        },
        "hardening": {
            "enabled": True,
            "initial_delay": 0,
            "audit_interval": 86400,
            "allowed_open_ports": [],
            "tls_expiry_warning_days": 30,
        },
        "alerting": {
            "enabled": True,
            "min_confidence": 40,
            "rate_limit": {"max_per_hour": 100, "cooldown_minutes": 0},
            "email": {"enabled": False},
            "webhook": {"enabled": False},
            "digest": {"enabled": False},
        },
    }


# ===================================================================
# 1. WebLogCollector tests
# ===================================================================

class TestWebLogCollector:
    """Test the web log collector tailing and parsing."""

    def test_parse_combined_log_line(self):
        """Verify combined format log line parsing."""
        from lonewarrior.collectors.weblog_collector import WebLogCollector

        line = (
            '192.168.1.50 - frank [10/Oct/2025:13:55:36 -0700] '
            '"GET /index.html HTTP/1.1" 200 2326 '
            '"http://example.com" "Mozilla/5.0"'
        )
        result = WebLogCollector._parse_line(line)

        assert result is not None
        assert result["source_ip"] == "192.168.1.50"
        assert result["method"] == "GET"
        assert result["url"] == "/index.html"
        assert result["status"] == 200
        assert result["user_agent"] == "Mozilla/5.0"

    def test_parse_returns_none_for_garbage(self):
        from lonewarrior.collectors.weblog_collector import WebLogCollector
        assert WebLogCollector._parse_line("not a log line") is None

    def test_parse_sqli_in_url(self):
        """Line with SQL injection payload should be flagged as suspicious."""
        from lonewarrior.collectors.weblog_collector import _SUSPICIOUS_HINTS

        line_url = "GET /search?q=1' OR 1=1-- HTTP/1.1"
        assert _SUSPICIOUS_HINTS.search(line_url) is not None

    def test_parse_xss_in_url(self):
        from lonewarrior.collectors.weblog_collector import _SUSPICIOUS_HINTS

        line_url = "GET /page?name=<script>alert(1)</script> HTTP/1.1"
        assert _SUSPICIOUS_HINTS.search(line_url) is not None

    def test_collector_tails_file(self, tmp_data_dir, db, event_bus, base_config):
        """Collector should publish web_request events from a real file."""
        from lonewarrior.core.state_manager import StateManager
        from lonewarrior.collectors.weblog_collector import WebLogCollector

        # Create a fake access log with an initial line (pre-existing)
        log_path = tmp_data_dir / "access.log"
        log_path.write_text(
            '10.0.0.99 - - [12/Apr/2026:00:00:00 +0000] '
            '"GET /old HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
        )

        config = dict(base_config)
        config["weblog"]["log_path"] = str(log_path)
        config["weblog"]["collection_interval"] = 1

        state_manager = StateManager(db, config)
        collector = WebLogCollector(config, db, event_bus, state_manager)

        received = []
        event_bus.subscribe("web_request", lambda e: received.append(e.data))

        # Run one manual collect cycle BEFORE start (so it seeks to end).
        # This ensures the seek happens synchronously before we write.
        collector.collect()

        # Now append a suspicious line — use URL-encoded SQLi payload
        # exactly as a real attacker would send it (+ = space in URLs)
        with open(log_path, "a") as f:
            f.write(
                '10.0.0.1 - - [12/Apr/2026:00:00:00 +0000] '
                '"GET /search?q=UNION+SELECT+1 HTTP/1.1" 200 512 '
                '"-" "Mozilla/5.0"\n'
            )
            f.flush()

        # Run another manual collect cycle
        collector.collect()

        # Wait for event bus dispatch
        time.sleep(1)
        collector.stop()

        assert len(received) >= 1, "Expected at least one web_request event"
        # Ensure we got the NEW line, not the old one
        new_events = [e for e in received if e["source_ip"] == "10.0.0.1"]
        assert len(new_events) >= 1, f"Expected event from 10.0.0.1, got IPs: {[e['source_ip'] for e in received]}"
        assert "UNION" in new_events[0]["url"]


# ===================================================================
# 2. WebLogAnalyzer tests
# ===================================================================

class TestWebLogAnalyzer:
    """Test OWASP attack pattern detection."""

    @pytest.fixture
    def analyzer(self, db, event_bus, base_config):
        from lonewarrior.core.state_manager import StateManager
        from lonewarrior.analyzers.weblog_analyzer import WebLogAnalyzer

        state_manager = StateManager(db, base_config)
        a = WebLogAnalyzer(base_config, db, event_bus, state_manager)
        a.start()
        yield a
        a.stop()

    def _make_web_event(self, event_bus, url="/", method="GET",
                        source_ip="10.0.0.1", user_agent="Mozilla/5.0",
                        status=200, referer="-"):
        """Publish a synthetic web_request event."""
        event_bus.publish(
            "web_request",
            {
                "source_ip": source_ip,
                "method": method,
                "url": url,
                "request": f"{method} {url} HTTP/1.1",
                "status": status,
                "referer": referer,
                "user_agent": user_agent,
                "raw_line": f'{source_ip} - - [12/Apr/2026:00:00:00 +0000] "{method} {url} HTTP/1.1" {status} 0 "{referer}" "{user_agent}"',
            },
            EventPriority.NORMAL,
            "test",
        )

    def test_sqli_detection(self, analyzer, db, event_bus):
        """SQL injection pattern should create a detection."""
        self._make_web_event(event_bus, url="/search?q=' UNION SELECT 1--")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        sqli = [d for d in detections if "SQL Injection" in d.description]
        assert len(sqli) >= 1, f"Expected SQLi detection, got: {[d.description for d in detections]}"

    def test_xss_detection(self, analyzer, db, event_bus):
        """XSS pattern should create a detection."""
        self._make_web_event(event_bus, url="/page?name=<script>alert(1)</script>")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        xss = [d for d in detections if "XSS" in d.description]
        assert len(xss) >= 1, f"Expected XSS detection, got: {[d.description for d in detections]}"

    def test_path_traversal_detection(self, analyzer, db, event_bus):
        """Path traversal should create a detection."""
        self._make_web_event(event_bus, url="/download?file=../../../../etc/passwd")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        lfi = [d for d in detections if "Path Traversal" in d.description]
        assert len(lfi) >= 1, f"Expected LFI detection, got: {[d.description for d in detections]}"

    def test_command_injection_detection(self, analyzer, db, event_bus):
        """Command injection should create a detection."""
        self._make_web_event(event_bus, url="/api?cmd=test; rm -rf /")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        cmdi = [d for d in detections if "Command Injection" in d.description]
        assert len(cmdi) >= 1, f"Expected CMDi detection, got: {[d.description for d in detections]}"

    def test_scanner_detection(self, analyzer, db, event_bus):
        """Known scanner user-agent should create a detection."""
        self._make_web_event(event_bus, url="/", user_agent="sqlmap/1.5")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        scanner = [d for d in detections if "Scanner" in d.description]
        assert len(scanner) >= 1, f"Expected scanner detection, got: {[d.description for d in detections]}"

    def test_rfi_detection(self, analyzer, db, event_bus):
        """Remote file inclusion should create a detection."""
        self._make_web_event(event_bus, url="/page?file=http://evil.com/shell.php")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        rfi = [d for d in detections if "Remote File Inclusion" in d.description]
        assert len(rfi) >= 1, f"Expected RFI detection, got: {[d.description for d in detections]}"

    def test_url_encoded_sqli_detection(self, analyzer, db, event_bus):
        """URL-encoded SQLi (+ for space, %27 for quote) should be detected."""
        # This is how real attacks look in access logs — URL-encoded
        self._make_web_event(event_bus, url="/search?q=%27+UNION+SELECT+password+FROM+users--")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        sqli = [d for d in detections if "SQL Injection" in d.description]
        assert len(sqli) >= 1, f"Expected SQLi detection from URL-encoded payload, got: {[d.description for d in detections]}"

    def test_percent_encoded_xss_detection(self, analyzer, db, event_bus):
        """Percent-encoded XSS (%3Cscript%3E) should be detected."""
        self._make_web_event(event_bus, url="/page?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        xss = [d for d in detections if "XSS" in d.description]
        assert len(xss) >= 1, f"Expected XSS detection from percent-encoded payload, got: {[d.description for d in detections]}"

    def test_double_encoded_traversal_detection(self, analyzer, db, event_bus):
        """Double-encoded path traversal (%252e%252e/) should be detected."""
        self._make_web_event(event_bus, url="/files?path=%252e%252e%252f%252e%252e%252fetc/passwd")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        lfi = [d for d in detections if "Path Traversal" in d.description or "passwd" in d.description.lower()]
        assert len(lfi) >= 1, f"Expected LFI detection from double-encoded payload, got: {[d.description for d in detections]}"

    def test_benign_request_no_detection(self, analyzer, db, event_bus):
        """Normal request should not create a detection."""
        self._make_web_event(event_bus, url="/index.html", user_agent="Mozilla/5.0")
        time.sleep(0.5)

        detections = db.get_detections(limit=50)
        assert len(detections) == 0, f"Expected no detections for benign request, got: {[d.description for d in detections]}"

    def test_rapid_404_detection(self, analyzer, db, event_bus):
        """Rapid 404s from same IP should trigger scanner detection."""
        for i in range(25):
            self._make_web_event(
                event_bus,
                url=f"/nonexistent_{i}",
                source_ip="10.0.0.99",
                status=404,
            )
            time.sleep(0.01)

        time.sleep(1)

        detections = db.get_detections(limit=100)
        scanner_404 = [d for d in detections if "rapid 404" in d.description.lower() or "scanner" in d.description.lower()]
        assert len(scanner_404) >= 1, f"Expected rapid-404 scanner detection, got: {[d.description for d in detections]}"

    def test_detection_publishes_event_for_confidence_scorer(self, analyzer, event_bus):
        """Detection should publish detection_created event for the ConfidenceScorer."""
        received = []
        event_bus.subscribe("detection_created", lambda e: received.append(e.data))

        self._make_web_event(event_bus, url="/search?q=' UNION SELECT 1--")
        time.sleep(0.5)

        assert len(received) >= 1, "Expected detection_created event"
        assert "source_ip" in received[0], "detection_created should include source_ip"
        assert received[0]["confidence"] > 0, "confidence should be > 0"


# ===================================================================
# 3. HardeningAuditor tests
# ===================================================================

class TestHardeningAuditor:
    """Test the server hardening audit module."""

    @pytest.fixture
    def auditor(self, db, event_bus, base_config):
        from lonewarrior.auditors.hardening_auditor import HardeningAuditor
        config = dict(base_config)
        config["hardening"]["initial_delay"] = 0
        config["hardening"]["audit_interval"] = 999999  # Don't repeat during test
        return HardeningAuditor(config, db, event_bus)

    def test_run_audit_returns_findings(self, auditor):
        """run_audit() should return a list of finding dicts."""
        findings = auditor.run_audit()
        assert isinstance(findings, list)
        # On any Linux system, there should be at least some findings
        # On Windows (CI), the checks gracefully skip so 0 is acceptable
        for f in findings:
            assert "category" in f
            assert "severity" in f
            assert "title" in f
            assert "description" in f
            assert "remediation" in f
            assert "passed" in f
            assert f["severity"] in ("critical", "high", "medium", "low", "info")

    def test_audit_publishes_event(self, auditor, event_bus):
        """Audit should publish hardening_audit_complete event via _publish_results."""
        received = []
        event_bus.subscribe("hardening_audit_complete", lambda e: received.append(e.data))

        findings = auditor.run_audit()
        # _publish_results and _store_results are called from _audit_loop,
        # not from run_audit. Call them directly to test.
        auditor._publish_results(findings)

        time.sleep(0.5)
        assert len(received) >= 1, "Expected hardening_audit_complete event"
        assert "total_checks" in received[0]
        assert "passed" in received[0]
        assert "failed" in received[0]

    def test_audit_stores_in_db(self, auditor, db):
        """Audit findings should be stored via _store_results."""
        findings = auditor.run_audit()
        auditor._store_results(findings)

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as cnt FROM audit_log WHERE event_type = 'hardening_audit'")
            count = cursor.fetchone()["cnt"]

        assert count >= 1, "Expected at least one audit_log entry"

    def test_ssh_check_with_insecure_config_file(self, auditor, tmp_data_dir):
        """SSH check should flag insecure settings when we point it at a test file.

        Since _check_ssh_config reads a hardcoded path (/etc/ssh/sshd_config),
        we patch the open call to inject a fake insecure config.
        """
        fake_config = textwrap.dedent("""\
            Port 22
            PermitRootLogin yes
            PasswordAuthentication yes
            PermitEmptyPasswords yes
            X11Forwarding yes
            MaxAuthTries 10
        """)

        from unittest.mock import mock_open
        with patch("builtins.open", mock_open(read_data=fake_config)):
            findings = auditor._check_ssh_config()

        failed = [f for f in findings if not f["passed"]]
        titles = {f["title"] for f in failed}

        assert any("root login" in t.lower() for t in titles), f"Expected root login finding, got {titles}"
        assert any("password" in t.lower() for t in titles), f"Expected password auth finding, got {titles}"

    def test_ssh_check_with_secure_config_file(self, auditor, tmp_data_dir):
        """SSH check should pass a properly hardened config."""
        fake_config = textwrap.dedent("""\
            Port 22
            PermitRootLogin no
            PasswordAuthentication no
            PermitEmptyPasswords no
            X11Forwarding no
            MaxAuthTries 3
            Protocol 2
        """)

        from unittest.mock import mock_open
        with patch("builtins.open", mock_open(read_data=fake_config)):
            findings = auditor._check_ssh_config()

        failed = [f for f in findings if not f["passed"]]
        assert len(failed) == 0, f"Secure config should pass all checks, but got: {[f['title'] for f in failed]}"

    def test_start_stop_lifecycle(self, auditor):
        """Auditor should start and stop cleanly."""
        auditor.start()
        time.sleep(0.5)
        assert auditor.running
        auditor.stop()
        assert not auditor.running


# ===================================================================
# 4. AlertManager tests
# ===================================================================

class TestAlertManager:
    """Test the alerting/notification system."""

    @pytest.fixture
    def alert_manager(self, db, event_bus, base_config):
        from lonewarrior.notifiers.alert_manager import AlertManager
        config = dict(base_config)
        config["alerting"] = {
            "enabled": True,
            "min_confidence": 40,
            "rate_limit": {"max_per_hour": 100, "cooldown_minutes": 0},
            "email": {"enabled": False},
            "webhook": {"enabled": False},
            "digest": {"enabled": False},
        }
        am = AlertManager(config, db, event_bus)
        am.start()
        yield am
        am.stop()

    def test_handle_detection_filters_low_confidence(self, alert_manager, event_bus):
        """Detections below min_confidence should not generate alerts."""
        alert_manager._enqueue_alert = MagicMock()

        # Below threshold (40)
        event = InternalEvent(
            event_type="detection_created",
            priority=EventPriority.HIGH,
            data={"confidence": 10, "description": "low conf", "detection_type": "test"},
            timestamp=datetime.now(timezone.utc),
            source="test",
        )
        alert_manager.handle_detection(event)
        alert_manager._enqueue_alert.assert_not_called()

    def test_handle_detection_passes_high_confidence(self, alert_manager, event_bus):
        """Detections above min_confidence should enqueue an alert."""
        alert_manager._enqueue_alert = MagicMock()

        event = InternalEvent(
            event_type="detection_created",
            priority=EventPriority.HIGH,
            data={"confidence": 80, "description": "high conf", "detection_type": "test"},
            timestamp=datetime.now(timezone.utc),
            source="test",
        )
        alert_manager.handle_detection(event)
        alert_manager._enqueue_alert.assert_called_once()

        payload = alert_manager._enqueue_alert.call_args[0][0]
        assert payload["severity"] == "critical"  # 80 >= 75

    def test_handle_action_always_alerts(self, alert_manager):
        """Action events should always generate alerts."""
        alert_manager._enqueue_alert = MagicMock()

        event = InternalEvent(
            event_type="action_executed",
            priority=EventPriority.HIGH,
            data={"action_type": "ip_block", "target": "10.0.0.1", "confidence": 0},
            timestamp=datetime.now(timezone.utc),
            source="test",
        )
        alert_manager.handle_action(event)
        alert_manager._enqueue_alert.assert_called_once()

    def test_webhook_payload_format(self, alert_manager):
        """Webhook JSON payload should have the expected structure."""
        captured = {}

        def mock_urlopen(req, timeout=None):
            captured["body"] = json.loads(req.data.decode("utf-8"))
            captured["headers"] = dict(req.headers)
            mock_resp = MagicMock()
            mock_resp.getcode.return_value = 200
            mock_resp.__enter__ = lambda s: mock_resp
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        alert_manager.alert_cfg["webhook"]["enabled"] = True
        alert_manager.alert_cfg["webhook"]["webhook_url"] = "https://hooks.example.com/test"

        with patch("lonewarrior.notifiers.alert_manager.urllib.request.urlopen", side_effect=mock_urlopen):
            alert_manager._send_webhook({
                "event_type": "detection",
                "severity": "high",
                "title": "Test Detection",
                "description": "Testing webhook",
                "confidence": 65,
                "action_taken": "ip_block",
                "target": "10.0.0.1",
                "timestamp": "2026-04-12T00:00:00+00:00",
                "source": "LoneWarrior",
            })

        assert captured["body"]["event_type"] == "detection"
        assert captured["body"]["severity"] == "high"
        assert captured["body"]["source"] == "LoneWarrior"
        assert captured["body"]["target"] == "10.0.0.1"

    def test_webhook_hmac_signature(self, alert_manager):
        """Webhook with hmac_secret should include X-LoneWarrior-Signature header."""
        import hashlib
        import hmac as hmac_mod

        captured = {}

        def mock_urlopen(req, timeout=None):
            captured["headers"] = dict(req.headers)
            captured["body_bytes"] = req.data
            mock_resp = MagicMock()
            mock_resp.getcode.return_value = 200
            mock_resp.__enter__ = lambda s: mock_resp
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        alert_manager.alert_cfg["webhook"]["enabled"] = True
        alert_manager.alert_cfg["webhook"]["webhook_url"] = "https://hooks.example.com/test"
        alert_manager.alert_cfg["webhook"]["hmac_secret"] = "my_secret_key"

        with patch("lonewarrior.notifiers.alert_manager.urllib.request.urlopen", side_effect=mock_urlopen):
            alert_manager._send_webhook({
                "event_type": "test",
                "severity": "low",
                "title": "HMAC Test",
                "description": "",
                "confidence": 0,
                "action_taken": None,
                "target": "",
                "timestamp": "2026-04-12T00:00:00+00:00",
                "source": "LoneWarrior",
            })

        assert "X-lonewarrior-signature" in captured["headers"]
        sig_header = captured["headers"]["X-lonewarrior-signature"]
        assert sig_header.startswith("sha256=")

        # Verify the signature
        expected_sig = hmac_mod.new(
            b"my_secret_key", captured["body_bytes"], hashlib.sha256
        ).hexdigest()
        assert sig_header == f"sha256={expected_sig}"

    def test_rate_limiting(self, db, event_bus, base_config):
        """Rate limiter should cap alerts per hour."""
        from lonewarrior.notifiers.alert_manager import AlertManager

        config = dict(base_config)
        config["alerting"] = {
            "enabled": True,
            "min_confidence": 0,
            "rate_limit": {"max_per_hour": 3, "cooldown_minutes": 0},
            "email": {"enabled": False},
            "webhook": {"enabled": True},
            "digest": {"enabled": False},
        }
        config["alerting"]["webhook"]["webhook_url"] = "https://hooks.example.com/test"

        am = AlertManager(config, db, event_bus)
        am.start()

        send_count = {"n": 0}

        def mock_urlopen(req, timeout=None):
            send_count["n"] += 1
            mock_resp = MagicMock()
            mock_resp.getcode.return_value = 200
            mock_resp.__enter__ = lambda s: mock_resp
            mock_resp.__exit__ = MagicMock(return_value=False)
            return mock_resp

        with patch("lonewarrior.notifiers.alert_manager.urllib.request.urlopen", side_effect=mock_urlopen):
            for i in range(10):
                am._enqueue_alert({
                    "event_type": "detection",
                    "severity": "high",
                    "title": f"Detection #{i}",
                    "description": "",
                    "confidence": 80,
                    "action_taken": None,
                    "target": f"10.0.0.{i}",  # Different targets to avoid cooldown
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source": "LoneWarrior",
                })
            time.sleep(2)

        am.stop()

        assert send_count["n"] <= 3, f"Expected max 3 sends (rate limit), got {send_count['n']}"

    def test_start_stop_lifecycle(self, db, event_bus, base_config):
        """AlertManager should start and stop without errors."""
        from lonewarrior.notifiers.alert_manager import AlertManager

        config = dict(base_config)
        am = AlertManager(config, db, event_bus)
        am.start()
        assert am._running
        time.sleep(0.3)
        am.stop()
        assert not am._running


# ===================================================================
# 5. Integration: WebLog -> Analyzer -> ConfidenceScorer -> Alert
# ===================================================================

class TestFullPipeline:
    """Test the full event pipeline: log -> collector -> analyzer -> scorer -> alert."""

    def test_sqli_triggers_detection_event(self, tmp_data_dir, db, event_bus, base_config):
        """
        Full pipeline: write SQLi line to log file -> WebLogCollector picks it up ->
        WebLogAnalyzer creates detection -> detection_created event fires.
        """
        from lonewarrior.core.state_manager import StateManager
        from lonewarrior.collectors.weblog_collector import WebLogCollector
        from lonewarrior.analyzers.weblog_analyzer import WebLogAnalyzer

        # Set up a log file
        log_path = tmp_data_dir / "access.log"
        log_path.write_text("")
        config = dict(base_config)
        config["weblog"]["log_path"] = str(log_path)

        state_manager = StateManager(db, config)

        # Start components
        collector = WebLogCollector(config, db, event_bus, state_manager)
        analyzer = WebLogAnalyzer(config, db, event_bus, state_manager)

        detection_events = []
        event_bus.subscribe("detection_created", lambda e: detection_events.append(e.data))

        collector.start()
        analyzer.start()

        # Wait for initial seek
        time.sleep(1)

        # Inject a malicious log line
        with open(log_path, "a") as f:
            f.write(
                '203.0.113.5 - - [12/Apr/2026:10:00:00 +0000] '
                '"GET /search?q=1%27+UNION+SELECT+password+FROM+users-- HTTP/1.1" 200 1024 '
                '"-" "Mozilla/5.0"\n'
            )

        # Wait for collection + analysis
        time.sleep(3)

        collector.stop()
        analyzer.stop()

        # Verify detection was created and event published
        assert len(detection_events) >= 1, "Expected detection_created event from SQLi"
        assert detection_events[0]["source_ip"] == "203.0.113.5"

        # Verify detection in database
        detections = db.get_detections(limit=50)
        sqli = [d for d in detections if "SQL" in d.description]
        assert len(sqli) >= 1

    def test_xss_triggers_alert_manager(self, tmp_data_dir, db, event_bus, base_config):
        """
        Full pipeline: XSS in log -> detection -> AlertManager receives it.
        """
        from lonewarrior.core.state_manager import StateManager
        from lonewarrior.collectors.weblog_collector import WebLogCollector
        from lonewarrior.analyzers.weblog_analyzer import WebLogAnalyzer
        from lonewarrior.notifiers.alert_manager import AlertManager

        log_path = tmp_data_dir / "access.log"
        log_path.write_text("")
        config = dict(base_config)
        config["weblog"]["log_path"] = str(log_path)
        config["alerting"]["enabled"] = True
        config["alerting"]["min_confidence"] = 0

        state_manager = StateManager(db, config)

        collector = WebLogCollector(config, db, event_bus, state_manager)
        analyzer = WebLogAnalyzer(config, db, event_bus, state_manager)
        alert_manager = AlertManager(config, db, event_bus)

        # Track what AlertManager enqueues
        enqueued = []
        original_enqueue = alert_manager._enqueue_alert
        def tracking_enqueue(payload):
            enqueued.append(payload)
            original_enqueue(payload)
        alert_manager._enqueue_alert = tracking_enqueue

        collector.start()
        analyzer.start()
        alert_manager.start()

        time.sleep(1)

        # Inject XSS attack
        with open(log_path, "a") as f:
            f.write(
                '198.51.100.1 - - [12/Apr/2026:10:00:00 +0000] '
                '"GET /page?q=<script>document.cookie</script> HTTP/1.1" 200 512 '
                '"-" "Mozilla/5.0"\n'
            )

        time.sleep(3)

        collector.stop()
        analyzer.stop()
        alert_manager.stop()

        assert len(enqueued) >= 1, "AlertManager should have received at least one alert"
        assert enqueued[0]["event_type"] == "detection"

    def test_multiple_attack_types_in_single_session(self, tmp_data_dir, db, event_bus, base_config):
        """
        Verify multiple attack types in one log batch each create separate detections.
        """
        from lonewarrior.core.state_manager import StateManager
        from lonewarrior.collectors.weblog_collector import WebLogCollector
        from lonewarrior.analyzers.weblog_analyzer import WebLogAnalyzer

        log_path = tmp_data_dir / "access.log"
        log_path.write_text("")
        config = dict(base_config)
        config["weblog"]["log_path"] = str(log_path)

        state_manager = StateManager(db, config)

        collector = WebLogCollector(config, db, event_bus, state_manager)
        analyzer = WebLogAnalyzer(config, db, event_bus, state_manager)

        collector.start()
        analyzer.start()
        time.sleep(1)

        # Multiple different attacks from same IP
        attacks = [
            "GET /search?q=1'+UNION+SELECT+1-- HTTP/1.1",            # SQLi
            "GET /page?x=<script>alert(1)</script> HTTP/1.1",         # XSS
            "GET /download?file=../../../../etc/passwd HTTP/1.1",      # LFI
            "GET /api?cmd=;+rm+-rf+/ HTTP/1.1",                       # CMDi
            "GET /page?file=http://evil.com/shell.php HTTP/1.1",      # RFI
        ]

        with open(log_path, "a") as f:
            for atk in attacks:
                f.write(
                    f'10.0.0.1 - - [12/Apr/2026:10:00:00 +0000] '
                    f'"{atk}" 200 512 "-" "Mozilla/5.0"\n'
                )

        time.sleep(3)

        collector.stop()
        analyzer.stop()

        detections = db.get_detections(limit=100)
        attack_types_found = set()
        for d in detections:
            desc = d.description.lower()
            if "sql" in desc:
                attack_types_found.add("sqli")
            if "xss" in desc:
                attack_types_found.add("xss")
            if "path traversal" in desc or "lfi" in desc:
                attack_types_found.add("lfi")
            if "command injection" in desc:
                attack_types_found.add("cmdi")
            if "remote file" in desc:
                attack_types_found.add("rfi")

        assert len(attack_types_found) >= 4, (
            f"Expected at least 4 different attack type detections, got {attack_types_found}"
        )


# ===================================================================
# 6. Engine integration test
# ===================================================================

class TestEngineIntegration:
    """Test that SecurityEngine initializes all new components."""

    def test_engine_init_with_new_modules(self, tmp_data_dir, base_config):
        """SecurityEngine should initialize weblog, hardening, and alerting components."""
        config = dict(base_config)
        config["general"]["data_dir"] = str(tmp_data_dir)
        config["general"]["log_dir"] = str(tmp_data_dir / "logs")
        config["weblog"]["enabled"] = True
        config["hardening"]["enabled"] = True
        config["alerting"]["enabled"] = True

        # Need full config keys that other components expect
        config.setdefault("file_integrity", {"enabled": False})
        config.setdefault("health", {"enabled": True, "check_interval": 30, "critical_services": [], "network_check_host": "8.8.8.8", "auto_rollback": True})
        config.setdefault("containment", {"auto_enable": False, "trigger_threshold": 75, "whitelist_ips": ["127.0.0.1"]})
        config.setdefault("threat_intel", {"use_builtin_blacklist": False, "external_feeds": {"enabled": False}, "reputation_tracking": False})
        config.setdefault("whitelists", {"processes": [], "users": [], "ips": ["127.0.0.1"], "domains": []})
        config.setdefault("network", {"track_destinations": True, "max_baseline_destinations": 1000})
        config.setdefault("phase_action_limits", {0: 50, 1: 50, 2: 75, 3: 100})
        config.setdefault("resources", {"max_memory_mb": 512})

        from lonewarrior.core.engine import SecurityEngine

        # Patch os.geteuid for Windows compatibility (privilege_helper uses it)
        with patch("os.geteuid", create=True, return_value=1000):
            engine = SecurityEngine(config)

        # Check new components exist
        collector_types = [c.__class__.__name__ for c in engine.collectors]
        analyzer_types = [a.__class__.__name__ for a in engine.analyzers]
        auxiliary_types = [a.__class__.__name__ for a in engine.auxiliary]

        assert "WebLogCollector" in collector_types, f"Missing WebLogCollector, got: {collector_types}"
        assert "WebLogAnalyzer" in analyzer_types, f"Missing WebLogAnalyzer, got: {analyzer_types}"
        assert "HardeningAuditor" in auxiliary_types, f"Missing HardeningAuditor, got: {auxiliary_types}"
        assert "AlertManager" in auxiliary_types, f"Missing AlertManager, got: {auxiliary_types}"
