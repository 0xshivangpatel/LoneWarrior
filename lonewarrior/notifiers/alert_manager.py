"""
Alert Manager - Notification system for LoneWarrior detections and actions

Sends alerts via Email (SMTP) and Webhooks (HTTP POST) when threats are
detected or autonomous actions are executed.  Designed for SMBs that install
LoneWarrior on a VPS and need to know when something happens without watching
a dashboard.

Features:
- Subscribes to detection_created and action_executed events on the EventBus
- Filters on severity / confidence thresholds to avoid alert fatigue
- Rate-limits per channel (max N alerts/hour) with per-target cooldown
- Queued sending via background thread (never blocks the event bus)
- Daily/weekly digest summary sent on a configurable schedule

All network I/O (SMTP, HTTP) uses 10-second timeouts and is wrapped in
try/except so alerting failures never crash the main agent.
"""

import hashlib
import hmac
import json
import logging
import queue
import smtplib
import ssl
import threading
import time
import urllib.request
import urllib.error
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

from lonewarrior.core.event_bus import EventBus, InternalEvent
from lonewarrior.storage.database import Database

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_ALERTING_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "min_confidence": 40,
    "rate_limit": {
        "max_per_hour": 10,
        "cooldown_minutes": 15,
    },
    "email": {
        "enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "use_ssl": False,
        "from_address": "",
        "to_addresses": [],
    },
    "webhook": {
        "enabled": False,
        "webhook_url": "",
        "headers": {},
        "hmac_secret": "",
    },
    "digest": {
        "enabled": True,
        "schedule": "daily",
        "hour": 9,
        "minute": 0,
    },
}

# Severity mapping based on confidence ranges
_SEVERITY_BANDS = [
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0, "low"),
]

NETWORK_TIMEOUT = 10  # seconds


def _confidence_to_severity(confidence: float) -> str:
    """Map a numeric confidence score to a severity label."""
    for threshold, label in _SEVERITY_BANDS:
        if confidence >= threshold:
            return label
    return "low"


def _merge_config(base: dict, override: dict) -> dict:
    """Recursively merge *override* into a copy of *base*."""
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _merge_config(merged[key], val)
        else:
            merged[key] = val
    return merged


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------

class AlertManager:
    """
    Central notification hub for LoneWarrior.

    Subscribes to ``detection_created`` and ``action_executed`` events,
    filters by confidence threshold, rate-limits, and dispatches
    notifications to Email and Webhook channels on a background thread.
    """

    def __init__(self, config: Dict[str, Any], database: Database, event_bus: EventBus):
        self.config = config
        self.db = database
        self.event_bus = event_bus

        # Merge user-supplied alerting section with defaults
        user_alerting = self.config.get("alerting", {})
        self.alert_cfg = _merge_config(_DEFAULT_ALERTING_CONFIG, user_alerting)

        # ---- Rate-limiting state ----
        self._rate_lock = threading.Lock()
        # channel -> list of timestamps (within the current hour window)
        self._send_timestamps: Dict[str, List[float]] = defaultdict(list)
        # "target:detection_type" -> last-alert timestamp (cooldown)
        self._cooldown_map: Dict[str, float] = {}

        # ---- Queued alerts waiting to be sent after rate-limit hit ----
        self._queued_summaries: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        # ---- Send queue (background thread consumes this) ----
        self._send_queue: queue.Queue = queue.Queue(maxsize=5000)

        # ---- Digest accumulator (reset after each digest send) ----
        self._digest_lock = threading.Lock()
        self._digest_detections: List[Dict[str, Any]] = []
        self._digest_actions: List[Dict[str, Any]] = []

        # ---- Threads ----
        self._running = False
        self._sender_thread: Optional[threading.Thread] = None
        self._digest_thread: Optional[threading.Thread] = None

        logger.info("AlertManager initialized (enabled=%s)", self.alert_cfg["enabled"])

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Start background sender and digest threads; subscribe to events."""
        if self._running:
            return

        self._running = True

        # Subscribe to events
        self.event_bus.subscribe("detection_created", self.handle_detection)
        self.event_bus.subscribe("action_executed", self.handle_action)

        # Background sender
        self._sender_thread = threading.Thread(
            target=self._sender_loop, daemon=True, name="AlertManager-sender"
        )
        self._sender_thread.start()

        # Digest timer
        if self.alert_cfg["digest"]["enabled"]:
            self._digest_thread = threading.Thread(
                target=self._digest_loop, daemon=True, name="AlertManager-digest"
            )
            self._digest_thread.start()

        logger.info("AlertManager started")

    def stop(self):
        """Stop threads and unsubscribe."""
        if not self._running:
            return

        logger.info("Stopping AlertManager ...")
        self._running = False

        # Unsubscribe
        try:
            self.event_bus.unsubscribe("detection_created", self.handle_detection)
        except Exception:
            pass
        try:
            self.event_bus.unsubscribe("action_executed", self.handle_action)
        except Exception:
            pass

        if self._sender_thread and self._sender_thread.is_alive():
            self._sender_thread.join(timeout=5.0)
        if self._digest_thread and self._digest_thread.is_alive():
            self._digest_thread.join(timeout=5.0)

        logger.info("AlertManager stopped")

    # ------------------------------------------------------------------
    # Event handlers (called on the EventBus dispatch thread)
    # ------------------------------------------------------------------

    def handle_detection(self, event: InternalEvent):
        """Handle a ``detection_created`` event.

        Only alerts when confidence >= min_confidence threshold.
        """
        if not self.alert_cfg["enabled"]:
            return

        try:
            data = event.data
            confidence = float(data.get("confidence", data.get("confidence_score", 0)))
            min_threshold = float(self.alert_cfg["min_confidence"])

            if confidence < min_threshold:
                logger.debug(
                    "Detection confidence %.1f below threshold %.1f - skipping alert",
                    confidence, min_threshold,
                )
                return

            severity = _confidence_to_severity(confidence)

            target = (
                data.get("ip")
                or data.get("remote_addr")
                or data.get("target")
                or data.get("key", "")
            )

            alert_payload = {
                "event_type": "detection",
                "severity": severity,
                "title": f"Threat Detected: {data.get('detection_type', 'unknown')}",
                "description": data.get("description", ""),
                "confidence": round(confidence, 1),
                "action_taken": None,
                "target": str(target),
                "timestamp": event.timestamp.isoformat(),
                "source": "LoneWarrior",
                "raw_data": data,
            }

            self._enqueue_alert(alert_payload)

            # Accumulate for digest
            with self._digest_lock:
                self._digest_detections.append(alert_payload)

        except Exception as exc:
            logger.error("AlertManager.handle_detection failed: %s", exc, exc_info=True)

    def handle_action(self, event: InternalEvent):
        """Handle an ``action_executed`` event.

        Always alerts on autonomous actions regardless of confidence.
        """
        if not self.alert_cfg["enabled"]:
            return

        try:
            data = event.data
            confidence = float(data.get("confidence", data.get("confidence_score", 0)))
            severity = _confidence_to_severity(confidence) if confidence > 0 else "high"

            alert_payload = {
                "event_type": "action",
                "severity": severity,
                "title": f"Action Executed: {data.get('action_type', 'unknown')}",
                "description": data.get("result", data.get("description", "")),
                "confidence": round(confidence, 1),
                "action_taken": data.get("action_type", "unknown"),
                "target": str(data.get("target", "")),
                "timestamp": event.timestamp.isoformat(),
                "source": "LoneWarrior",
                "raw_data": data,
            }

            self._enqueue_alert(alert_payload)

            # Accumulate for digest
            with self._digest_lock:
                self._digest_actions.append(alert_payload)

        except Exception as exc:
            logger.error("AlertManager.handle_action failed: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _cooldown_key(self, payload: Dict[str, Any]) -> str:
        """Build a dedup key for per-target cooldown."""
        target = payload.get("target", "")
        etype = payload.get("event_type", "")
        title = payload.get("title", "")
        return f"{target}:{etype}:{title}"

    def _is_rate_limited(self, channel: str) -> bool:
        """Return True if *channel* has exhausted its hourly quota."""
        max_per_hour = int(self.alert_cfg["rate_limit"]["max_per_hour"])
        now = time.monotonic()
        window = 3600.0  # 1 hour

        with self._rate_lock:
            timestamps = self._send_timestamps[channel]
            # Prune old entries outside the window
            self._send_timestamps[channel] = [
                ts for ts in timestamps if now - ts < window
            ]
            return len(self._send_timestamps[channel]) >= max_per_hour

    def _record_send(self, channel: str):
        """Record a successful send for rate-limit tracking."""
        with self._rate_lock:
            self._send_timestamps[channel].append(time.monotonic())

    def _is_in_cooldown(self, payload: Dict[str, Any]) -> bool:
        """Return True if the same target/detection was alerted recently."""
        key = self._cooldown_key(payload)
        cooldown_sec = int(self.alert_cfg["rate_limit"]["cooldown_minutes"]) * 60
        now = time.monotonic()

        with self._rate_lock:
            last = self._cooldown_map.get(key)
            if last is not None and (now - last) < cooldown_sec:
                return True
            return False

    def _mark_cooldown(self, payload: Dict[str, Any]):
        """Mark that an alert was sent for this target/detection."""
        key = self._cooldown_key(payload)
        with self._rate_lock:
            self._cooldown_map[key] = time.monotonic()

    # ------------------------------------------------------------------
    # Enqueue / Send loop
    # ------------------------------------------------------------------

    def _enqueue_alert(self, payload: Dict[str, Any]):
        """Put an alert payload onto the send queue (non-blocking)."""
        try:
            self._send_queue.put_nowait(payload)
        except queue.Full:
            logger.warning("Alert send queue full - dropping alert: %s", payload.get("title"))

    def _sender_loop(self):
        """Background thread that drains the send queue."""
        logger.info("Alert sender thread started")

        while self._running:
            try:
                payload = self._send_queue.get(timeout=1.0)
            except queue.Empty:
                # Periodically flush queued (rate-limited) summaries
                self._flush_queued_summaries()
                continue

            try:
                self._dispatch_alert(payload)
            except Exception as exc:
                logger.error("Alert dispatch failed: %s", exc, exc_info=True)
            finally:
                self._send_queue.task_done()

        # Drain remaining items on shutdown
        while not self._send_queue.empty():
            try:
                payload = self._send_queue.get_nowait()
                self._dispatch_alert(payload)
                self._send_queue.task_done()
            except Exception:
                break

        logger.info("Alert sender thread stopped")

    def _dispatch_alert(self, payload: Dict[str, Any]):
        """Route a single alert to all enabled channels, respecting limits."""

        # Per-target cooldown check
        if self._is_in_cooldown(payload):
            logger.debug("Alert in cooldown, queuing for batch summary: %s", payload.get("title"))
            self._queue_for_summary(payload)
            return

        channels_sent = False

        # --- Email ---
        if self.alert_cfg["email"]["enabled"]:
            if self._is_rate_limited("email"):
                logger.debug("Email rate-limited, queuing for batch summary")
                self._queue_for_summary(payload, channel="email")
            else:
                try:
                    self._send_email(payload)
                    self._record_send("email")
                    channels_sent = True
                except Exception as exc:
                    logger.error("Email send failed: %s", exc, exc_info=True)

        # --- Webhook ---
        if self.alert_cfg["webhook"]["enabled"]:
            if self._is_rate_limited("webhook"):
                logger.debug("Webhook rate-limited, queuing for batch summary")
                self._queue_for_summary(payload, channel="webhook")
            else:
                try:
                    self._send_webhook(payload)
                    self._record_send("webhook")
                    channels_sent = True
                except Exception as exc:
                    logger.error("Webhook send failed: %s", exc, exc_info=True)

        if channels_sent:
            self._mark_cooldown(payload)

    def _queue_for_summary(self, payload: Dict[str, Any], channel: str = "all"):
        """Queue a rate-limited alert for later batch summary."""
        with self._rate_lock:
            self._queued_summaries[channel].append(payload)

    def _flush_queued_summaries(self):
        """If there are queued alerts whose rate-limit window has opened, send a batch."""
        with self._rate_lock:
            channels_to_flush = []
            for channel, items in self._queued_summaries.items():
                if items and not self._is_rate_limited_unlocked(channel):
                    channels_to_flush.append(channel)

            if not channels_to_flush:
                return

            for channel in channels_to_flush:
                items = self._queued_summaries.pop(channel, [])
                if not items:
                    continue
                # Release lock before sending
                summary = self._build_batch_summary(items)

        # Send outside the lock
        for channel in channels_to_flush:
            try:
                if channel in ("email", "all") and self.alert_cfg["email"]["enabled"]:
                    self._send_email(summary)
                    self._record_send("email")
                if channel in ("webhook", "all") and self.alert_cfg["webhook"]["enabled"]:
                    self._send_webhook(summary)
                    self._record_send("webhook")
            except Exception as exc:
                logger.error("Batch summary send failed for %s: %s", channel, exc, exc_info=True)

    def _is_rate_limited_unlocked(self, channel: str) -> bool:
        """Rate-limit check without acquiring lock (caller holds it)."""
        max_per_hour = int(self.alert_cfg["rate_limit"]["max_per_hour"])
        now = time.monotonic()
        window = 3600.0
        timestamps = self._send_timestamps.get(channel, [])
        self._send_timestamps[channel] = [ts for ts in timestamps if now - ts < window]
        return len(self._send_timestamps[channel]) >= max_per_hour

    def _build_batch_summary(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Collapse a list of queued alerts into a single summary payload."""
        detection_count = sum(1 for i in items if i.get("event_type") == "detection")
        action_count = sum(1 for i in items if i.get("event_type") == "action")
        targets = list({i.get("target", "unknown") for i in items if i.get("target")})

        highest_severity = "low"
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        for item in items:
            sev = item.get("severity", "low")
            if severity_order.get(sev, 0) > severity_order.get(highest_severity, 0):
                highest_severity = sev

        description_lines = []
        for item in items[:20]:  # Cap summary detail at 20 entries
            description_lines.append(
                f"- [{item.get('severity', '?').upper()}] {item.get('title', '?')} "
                f"(target: {item.get('target', 'N/A')})"
            )
        if len(items) > 20:
            description_lines.append(f"- ... and {len(items) - 20} more alerts")

        return {
            "event_type": "batch_summary",
            "severity": highest_severity,
            "title": f"LoneWarrior Alert Batch: {len(items)} alerts "
                     f"({detection_count} detections, {action_count} actions)",
            "description": "\n".join(description_lines),
            "confidence": 0,
            "action_taken": None,
            "target": ", ".join(targets[:10]),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "LoneWarrior",
        }

    # ------------------------------------------------------------------
    # Email channel
    # ------------------------------------------------------------------

    def _send_email(self, payload: Dict[str, Any]):
        """Send an HTML-formatted email alert via SMTP."""
        cfg = self.alert_cfg["email"]
        smtp_host = cfg["smtp_host"]
        smtp_port = int(cfg["smtp_port"])
        smtp_user = cfg["smtp_user"]
        smtp_password = cfg["smtp_password"]
        from_addr = cfg["from_address"]
        to_addrs = cfg["to_addresses"]
        use_ssl = cfg.get("use_ssl", False)

        if not smtp_host or not to_addrs:
            logger.warning("Email alerting enabled but smtp_host or to_addresses not configured")
            return

        subject = self._email_subject(payload)
        html_body = self._email_html_body(payload)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg.attach(MIMEText(self._email_plain_body(payload), "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        context = ssl.create_default_context()

        try:
            if use_ssl:
                # Direct SSL connection (port 465)
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=NETWORK_TIMEOUT,
                                       context=context) as server:
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    server.sendmail(from_addr, to_addrs, msg.as_string())
            else:
                # STARTTLS (port 587)
                with smtplib.SMTP(smtp_host, smtp_port, timeout=NETWORK_TIMEOUT) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    server.sendmail(from_addr, to_addrs, msg.as_string())

            logger.info("Email alert sent: %s", subject)
        except Exception as exc:
            logger.error("SMTP send failed (%s:%d): %s", smtp_host, smtp_port, exc)
            raise

    @staticmethod
    def _email_subject(payload: Dict[str, Any]) -> str:
        severity = payload.get("severity", "info").upper()
        title = payload.get("title", "Alert")
        return f"[LoneWarrior {severity}] {title}"

    @staticmethod
    def _email_plain_body(payload: Dict[str, Any]) -> str:
        lines = [
            f"LoneWarrior Security Alert",
            f"==========================",
            f"",
            f"Type:        {payload.get('event_type', 'N/A')}",
            f"Severity:    {payload.get('severity', 'N/A').upper()}",
            f"Title:       {payload.get('title', 'N/A')}",
            f"Description: {payload.get('description', 'N/A')}",
            f"Confidence:  {payload.get('confidence', 'N/A')}",
            f"Action:      {payload.get('action_taken', 'none')}",
            f"Target:      {payload.get('target', 'N/A')}",
            f"Timestamp:   {payload.get('timestamp', 'N/A')}",
            f"",
            f"--",
            f"Sent by LoneWarrior Security Agent",
        ]
        return "\n".join(lines)

    @staticmethod
    def _email_html_body(payload: Dict[str, Any]) -> str:
        severity = payload.get("severity", "info")
        color_map = {
            "critical": "#d32f2f",
            "high": "#e65100",
            "medium": "#f9a825",
            "low": "#2e7d32",
        }
        badge_color = color_map.get(severity, "#757575")

        description = payload.get("description", "N/A")
        # Escape basic HTML entities in description
        description = (
            description.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br>")
        )

        return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             margin: 0; padding: 20px; background: #f5f5f5;">
  <div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px;
              overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">

    <!-- Header -->
    <div style="background: {badge_color}; color: #fff; padding: 16px 24px;">
      <h2 style="margin: 0; font-size: 18px;">
        LoneWarrior Alert &mdash; {severity.upper()}
      </h2>
    </div>

    <!-- Body -->
    <div style="padding: 24px;">
      <h3 style="margin: 0 0 12px 0; color: #333;">
        {payload.get('title', 'Security Alert')}
      </h3>

      <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
        <tr>
          <td style="padding: 8px 0; color: #666; width: 130px;">Event Type</td>
          <td style="padding: 8px 0; color: #222;">{payload.get('event_type', 'N/A')}</td>
        </tr>
        <tr style="background: #fafafa;">
          <td style="padding: 8px 0; color: #666;">Confidence</td>
          <td style="padding: 8px 0; color: #222; font-weight: bold;">{payload.get('confidence', 'N/A')}</td>
        </tr>
        <tr>
          <td style="padding: 8px 0; color: #666;">Action Taken</td>
          <td style="padding: 8px 0; color: #222;">{payload.get('action_taken', 'none') or 'none'}</td>
        </tr>
        <tr style="background: #fafafa;">
          <td style="padding: 8px 0; color: #666;">Target</td>
          <td style="padding: 8px 0; color: #222; font-family: monospace;">{payload.get('target', 'N/A')}</td>
        </tr>
        <tr>
          <td style="padding: 8px 0; color: #666;">Timestamp</td>
          <td style="padding: 8px 0; color: #222;">{payload.get('timestamp', 'N/A')}</td>
        </tr>
      </table>

      <div style="margin-top: 16px; padding: 12px; background: #f9f9f9; border-left: 4px solid {badge_color};
                  font-size: 14px; color: #444;">
        <strong>Details:</strong><br>{description}
      </div>
    </div>

    <!-- Footer -->
    <div style="padding: 12px 24px; background: #fafafa; font-size: 12px; color: #999;
                border-top: 1px solid #eee;">
      Sent by LoneWarrior Security Agent &bull; Do not reply to this email
    </div>
  </div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Webhook channel
    # ------------------------------------------------------------------

    def _send_webhook(self, payload: Dict[str, Any]):
        """Send a JSON POST to the configured webhook URL."""
        cfg = self.alert_cfg["webhook"]
        url = cfg.get("webhook_url", "")
        extra_headers = cfg.get("headers", {}) or {}
        hmac_secret = cfg.get("hmac_secret", "")

        if not url:
            logger.warning("Webhook alerting enabled but webhook_url not configured")
            return

        # Build the outbound JSON (strip raw_data to keep payload clean)
        out = {
            "event_type": payload.get("event_type"),
            "severity": payload.get("severity"),
            "title": payload.get("title"),
            "description": payload.get("description"),
            "confidence": payload.get("confidence"),
            "action_taken": payload.get("action_taken"),
            "target": payload.get("target"),
            "timestamp": payload.get("timestamp"),
            "source": "LoneWarrior",
        }
        body = json.dumps(out, default=str).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "LoneWarrior-AlertManager/1.0",
        }
        headers.update(extra_headers)

        # HMAC signature (SHA-256)
        if hmac_secret:
            sig = hmac.new(
                hmac_secret.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            headers["X-LoneWarrior-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(
            url, data=body, headers=headers, method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT) as resp:
                status = resp.getcode()
                if status and status >= 400:
                    logger.warning("Webhook returned HTTP %d", status)
                else:
                    logger.info("Webhook alert sent (HTTP %s): %s", status, out.get("title"))
        except urllib.error.HTTPError as exc:
            logger.error("Webhook HTTP error %d: %s", exc.code, exc.reason)
            raise
        except Exception as exc:
            logger.error("Webhook request failed (%s): %s", url, exc)
            raise

    # ------------------------------------------------------------------
    # Digest
    # ------------------------------------------------------------------

    def _digest_loop(self):
        """Background thread that sends periodic digest summaries."""
        logger.info("Digest thread started (schedule=%s, hour=%d:%02d)",
                     self.alert_cfg["digest"]["schedule"],
                     self.alert_cfg["digest"]["hour"],
                     self.alert_cfg["digest"]["minute"])

        while self._running:
            try:
                now = datetime.now(timezone.utc)
                target_time = self._next_digest_time(now)
                wait_seconds = (target_time - now).total_seconds()

                # Sleep in small increments so we can respond to stop()
                while self._running and wait_seconds > 0:
                    sleep_chunk = min(wait_seconds, 30.0)
                    time.sleep(sleep_chunk)
                    wait_seconds -= sleep_chunk

                if not self._running:
                    break

                self._send_digest()

            except Exception as exc:
                logger.error("Digest loop error: %s", exc, exc_info=True)
                # Avoid tight spin on persistent error
                time.sleep(60)

        logger.info("Digest thread stopped")

    def _next_digest_time(self, now: datetime) -> datetime:
        """Compute the next digest send time after *now*."""
        schedule = self.alert_cfg["digest"].get("schedule", "daily")
        hour = int(self.alert_cfg["digest"].get("hour", 9))
        minute = int(self.alert_cfg["digest"].get("minute", 0))

        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

        if schedule == "weekly":
            # Next Monday at the configured time
            days_ahead = (7 - now.weekday()) % 7  # 0 = Monday
            if days_ahead == 0 and now >= candidate:
                days_ahead = 7
            candidate += timedelta(days=days_ahead)
        else:
            # Daily
            if now >= candidate:
                candidate += timedelta(days=1)

        return candidate

    def _send_digest(self):
        """Build and send the digest summary."""
        with self._digest_lock:
            detections = list(self._digest_detections)
            actions = list(self._digest_actions)
            self._digest_detections.clear()
            self._digest_actions.clear()

        # Also pull recent data from the database for richer summaries
        db_detections = []
        db_actions = []
        try:
            db_detections = self.db.get_detections(limit=500)
            db_actions = self.db.get_actions(limit=500)
        except Exception as exc:
            logger.error("Failed to query DB for digest: %s", exc)

        # Top blocked IPs
        ip_block_counts: Dict[str, int] = defaultdict(int)
        for action in db_actions:
            if action.action_type == "ip_block" and action.status == "success":
                ip_block_counts[action.target] += 1

        top_ips = sorted(ip_block_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Severity distribution from in-memory accumulator
        severity_counts: Dict[str, int] = defaultdict(int)
        for d in detections:
            severity_counts[d.get("severity", "low")] += 1

        # Build digest payload
        schedule = self.alert_cfg["digest"].get("schedule", "daily")
        period_label = "Daily" if schedule == "daily" else "Weekly"

        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        all_clear = len(detections) == 0 and len(actions) == 0

        if all_clear:
            title = f"{period_label} Digest ({now_str}) - All Clear"
            description = (
                "No threats were detected and no autonomous actions were taken "
                "during this period. LoneWarrior is running and monitoring your system."
            )
        else:
            title = (
                f"{period_label} Digest ({now_str}) - "
                f"{len(detections)} detections, {len(actions)} actions"
            )

            lines = [
                f"Period detections: {len(detections)}",
                f"Period actions: {len(actions)}",
            ]
            if severity_counts:
                sev_line = ", ".join(
                    f"{sev}: {cnt}" for sev, cnt in sorted(
                        severity_counts.items(),
                        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x[0], 9),
                    )
                )
                lines.append(f"Severity breakdown: {sev_line}")

            if top_ips:
                lines.append("Top blocked IPs:")
                for ip, cnt in top_ips:
                    lines.append(f"  {ip}: {cnt} blocks")

            # DB-level totals
            lines.append(f"Total detections in DB: {len(db_detections)}")
            lines.append(f"Total actions in DB: {len(db_actions)}")

            description = "\n".join(lines)

        digest_payload = {
            "event_type": "digest",
            "severity": "low" if all_clear else "medium",
            "title": title,
            "description": description,
            "confidence": 0,
            "action_taken": None,
            "target": "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "LoneWarrior",
        }

        # Send via all enabled channels (bypass rate limiter for digests)
        if self.alert_cfg["email"]["enabled"]:
            try:
                self._send_email(digest_payload)
            except Exception as exc:
                logger.error("Digest email failed: %s", exc, exc_info=True)

        if self.alert_cfg["webhook"]["enabled"]:
            try:
                self._send_webhook(digest_payload)
            except Exception as exc:
                logger.error("Digest webhook failed: %s", exc, exc_info=True)

        logger.info("Digest sent: %s", title)

    # ------------------------------------------------------------------
    # Manual trigger (for CLI / web dashboard)
    # ------------------------------------------------------------------

    def send_test_alert(self):
        """Send a test alert to verify configuration."""
        test_payload = {
            "event_type": "test",
            "severity": "low",
            "title": "Test Alert - LoneWarrior Alerting Configured",
            "description": (
                "This is a test notification from LoneWarrior. "
                "If you received this, your alerting is configured correctly."
            ),
            "confidence": 0,
            "action_taken": None,
            "target": "N/A",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "LoneWarrior",
        }

        errors = []

        if self.alert_cfg["email"]["enabled"]:
            try:
                self._send_email(test_payload)
            except Exception as exc:
                errors.append(f"Email: {exc}")

        if self.alert_cfg["webhook"]["enabled"]:
            try:
                self._send_webhook(test_payload)
            except Exception as exc:
                errors.append(f"Webhook: {exc}")

        if errors:
            raise RuntimeError("; ".join(errors))
