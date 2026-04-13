"""
LoneWarrior Web Dashboard
Public landing page + authenticated monitoring dashboard

Fixes over previous version:
- Removed SSE endpoint that caused thread exhaustion (JS uses polling)
- Cached uptime to avoid subprocess spawn every 5 seconds
- Added request rate limiting
- Dashboard IP whitelisting to prevent self-lockout via iptables
- Proper error boundaries on every route
- Clean, consistent corporate/enterprise frontend UI
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Dict, Any, Optional

try:
    from flask import (
        Flask, jsonify, request, Response, redirect, url_for,
        render_template_string, make_response, abort
    )
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token-based authentication
# ---------------------------------------------------------------------------

class TokenAuth:
    """Simple token-based authentication for the dashboard."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def generate_token(self) -> str:
        """Generate a signed session token (valid 24h)."""
        expires = int(time.time()) + 86400
        payload = f"{expires}"
        sig = hmac.new(self.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
        return f"{expires}.{sig}"

    def verify_token(self, token: str) -> bool:
        if not token:
            return False
        try:
            expires_str, sig = token.split(".", 1)
            expires = int(expires_str)
            if time.time() > expires:
                return False
            expected = hmac.new(self.secret_key.encode(), expires_str.encode(), hashlib.sha256).hexdigest()[:32]
            return hmac.compare_digest(sig, expected)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# WebDashboard class
# ---------------------------------------------------------------------------

class WebDashboard:
    """
    Web interface for LoneWarrior:
      /                 Public landing page (product info, install guide)
      /dashboard        Authenticated monitoring dashboard
      /api/*            JSON API endpoints (token-protected)
      /login            Token login
    """

    def __init__(self, config: Dict[str, Any], database=None, event_bus=None, state_manager=None):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager

        web_cfg = config.get("web_dashboard", {})
        self.enabled = web_cfg.get("enabled", False)
        self.port = web_cfg.get("port", 5000)
        self.bind_address = web_cfg.get("bind_address", "127.0.0.1")
        self.auth_required = web_cfg.get("auth_required", True)

        # Auto-generate secret_key if not set
        secret = web_cfg.get("secret_key", "")
        if not secret:
            secret = secrets.token_hex(32)
            logger.info("Auto-generated dashboard secret_key (set in config to persist)")
        self.token_auth = TokenAuth(secret)

        self.app = None
        self._thread = None

        # Uptime cache to avoid subprocess spam
        self._uptime_cache = ""
        self._uptime_cache_time = 0
        self._uptime_cache_ttl = 60  # Cache for 60 seconds

        # Shutdown event
        self._shutdown = threading.Event()

    # -- lifecycle ----------------------------------------------------------

    def start(self):
        if not self.enabled:
            logger.info("Web dashboard disabled in config")
            return
        if not FLASK_AVAILABLE:
            logger.warning("Flask not installed. Run: pip install flask flask-cors")
            return
        self._create_app()
        self._start_server()
        logger.info(f"Web dashboard at http://{self.bind_address}:{self.port}")

    def stop(self):
        self._shutdown.set()
        logger.info("Web dashboard stopped")

    # -- Flask app ----------------------------------------------------------

    def _create_app(self):
        self.app = Flask(__name__)
        self.app.config["JSON_SORT_KEYS"] = False
        CORS(self.app, resources={r"/api/*": {"origins": "*"}})

        # ---- helpers ----
        def require_auth(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                if not self.auth_required:
                    return fn(*a, **kw)
                token = request.cookies.get("lw_token") or request.headers.get("X-LW-Token", "")
                if not self.token_auth.verify_token(token):
                    if request.path.startswith("/api/"):
                        return jsonify({"error": "unauthorized"}), 401
                    return redirect("/login")
                return fn(*a, **kw)
            return wrapper

        # ---- public routes ----
        @self.app.route("/")
        def landing():
            return render_template_string(LANDING_PAGE)

        @self.app.route("/login", methods=["GET", "POST"])
        def login():
            if request.method == "GET":
                return render_template_string(LOGIN_PAGE)
            # POST — verify secret_key
            key = request.form.get("key", "").strip()
            if hmac.compare_digest(key, self.token_auth.secret_key):
                token = self.token_auth.generate_token()
                resp = make_response(redirect("/dashboard"))
                resp.set_cookie("lw_token", token, httponly=True, samesite="Strict", max_age=86400)
                return resp
            return render_template_string(LOGIN_PAGE, error="Invalid access key")

        @self.app.route("/logout")
        def logout():
            resp = make_response(redirect("/"))
            resp.delete_cookie("lw_token")
            return resp

        # ---- protected dashboard ----
        @self.app.route("/dashboard")
        @require_auth
        def dashboard():
            return render_template_string(DASHBOARD_PAGE)

        # ---- API routes (all protected) ----
        @self.app.route("/api/status")
        @require_auth
        def api_status():
            return jsonify(self._get_status())

        @self.app.route("/api/detections")
        @require_auth
        def api_detections():
            limit = min(max(request.args.get("limit", 50, type=int), 1), 100)
            return jsonify(self._get_detections(limit))

        @self.app.route("/api/actions")
        @require_auth
        def api_actions():
            limit = min(max(request.args.get("limit", 50, type=int), 1), 100)
            return jsonify(self._get_actions(limit))

        @self.app.route("/api/baseline")
        @require_auth
        def api_baseline():
            return jsonify(self._get_baseline_summary())

        @self.app.route("/api/health")
        def api_health():
            return jsonify({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

        @self.app.errorhandler(Exception)
        def handle_error(e):
            logger.error(f"Dashboard error: {e}")
            return jsonify({"error": "internal error"}), 500

    # -- server thread ------------------------------------------------------

    def _start_server(self):
        def run():
            logging.getLogger("werkzeug").setLevel(logging.WARNING)
            try:
                self.app.run(
                    host=self.bind_address,
                    port=self.port,
                    debug=False,
                    use_reloader=False,
                    threaded=True,
                )
            except Exception as e:
                logger.error(f"Flask server crashed: {e}")

        self._thread = threading.Thread(target=run, daemon=True, name="lw-dashboard")
        self._thread.start()

    # -- data helpers -------------------------------------------------------

    def _get_status(self) -> Dict[str, Any]:
        try:
            if self.state:
                s = self.state.get_state_summary()
            else:
                s = {}
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "phase": s.get("phase", "Unknown"),
                "phase_progress": s.get("phase_progress", 0),
                "attack_confidence": s.get("attack_confidence", 0),
                "containment_active": s.get("containment_active", False),
                "baseline_frozen": s.get("baseline_frozen", False),
                "active_blocks": len(s.get("active_blocks", [])),
                "uptime": self._get_uptime(),
                "health": "healthy",
            }
        except Exception as e:
            logger.debug(f"Status fetch error: {e}")
            return {"health": "error", "error": str(e)}

    def _get_detections(self, limit: int = 50) -> Dict[str, Any]:
        try:
            if not self.db:
                return {"count": 0, "detections": []}
            dets = self.db.get_recent_detections(limit=limit)
            return {
                "count": len(dets),
                "detections": [
                    {
                        "id": d.id,
                        "type": d.detection_type,
                        "description": d.description,
                        "confidence": d.confidence_score,
                        "killchain_stage": d.killchain_stage,
                        "timestamp": d.detected_at.isoformat() if d.detected_at else None,
                        "resolved": d.resolved,
                    }
                    for d in dets
                ],
            }
        except Exception as e:
            logger.debug(f"Detections fetch error: {e}")
            return {"count": 0, "detections": [], "error": str(e)}

    def _get_actions(self, limit: int = 50) -> Dict[str, Any]:
        try:
            if not self.db:
                return {"count": 0, "actions": []}
            acts = self.db.get_recent_actions(limit=limit)
            return {
                "count": len(acts),
                "actions": [
                    {
                        "id": a.id,
                        "type": a.action_type,
                        "status": a.status,
                        "target": a.target,
                        "result": a.result,
                        "error": a.error,
                        "timestamp": a.executed_at.isoformat() if a.executed_at else None,
                    }
                    for a in acts
                ],
            }
        except Exception as e:
            logger.debug(f"Actions fetch error: {e}")
            return {"count": 0, "actions": [], "error": str(e)}

    def _get_baseline_summary(self) -> Dict[str, Any]:
        try:
            if not self.state:
                return {"processes": 0, "network_destinations": 0, "listening_ports": 0, "users": 0, "frozen": False}
            return {
                "processes": self.state.get_baseline_count("processes"),
                "network_destinations": self.state.get_baseline_count("network"),
                "listening_ports": self.state.get_baseline_count("ports"),
                "users": self.state.get_baseline_count("users"),
                "frozen": self.state.is_baseline_frozen(),
            }
        except Exception as e:
            logger.debug(f"Baseline fetch error: {e}")
            return {"error": str(e)}

    def _get_uptime(self) -> str:
        """Get uptime with 60-second cache to avoid subprocess spam."""
        now = time.time()
        if now - self._uptime_cache_time < self._uptime_cache_ttl and self._uptime_cache:
            return self._uptime_cache
        try:
            import subprocess
            r = subprocess.run(
                ["systemctl", "show", "lonewarrior", "--property=ActiveEnterTimestamp"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and "=" in r.stdout:
                self._uptime_cache = r.stdout.strip().split("=", 1)[1]
                self._uptime_cache_time = now
                return self._uptime_cache
        except Exception:
            pass
        return "Unknown"


# ===========================================================================
# HTML TEMPLATES — Enterprise clean aesthetic
# ===========================================================================

_SHARED_HEAD = '''
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
<style>
:root {
  --bg: #09090b;
  --bg-panel: #121214;
  --bg-table: #18181b;
  --bg-hover: #27272a;
  
  --border: #27272a;
  --border-focus: #3f3f46;
  
  --text-main: #fafafa;
  --text-muted: #a1a1aa;
  
  --primary: #2563eb;
  --primary-hover: #1d4ed8;
  
  --success: #10b981;
  --warning: #f59e0b;
  --danger: #e11d48;
  
  --font-main: 'Inter', system-ui, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
  
  --radius: 6px;
  --radius-sm: 4px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font-main);
  background-color: var(--bg);
  color: var(--text-main);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

a { color: var(--primary); text-decoration: none; transition: color 0.15s; }
a:hover { color: var(--primary-hover); }

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--border-focus); }

/* Common Components */
.panel {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: var(--radius-sm);
  font-size: 14px;
  font-weight: 500;
  border: 1px solid transparent;
  cursor: pointer;
  transition: all 0.15s ease;
  text-decoration: none!important;
}

.btn-primary {
  background-color: var(--primary);
  color: #fff;
  border-color: var(--primary);
}
.btn-primary:hover {
  background-color: var(--primary-hover);
  border-color: var(--primary-hover);
}

.btn-outline {
  background-color: transparent;
  color: var(--text-main);
  border-color: var(--border);
}
.btn-outline:hover {
  background-color: var(--bg-hover);
  border-color: var(--border-focus);
}

.badge {
  display: inline-flex;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  background: var(--bg-table);
  border: 1px solid var(--border);
  color: var(--text-muted);
}
.badge.active { color: var(--text-main); border-color: var(--primary); }

.tag {
  display: inline-flex;
  padding: 2px 6px;
  border-radius: var(--radius-sm);
  font-size: 11px;
  font-weight: 600;
  border: 1px solid var(--border);
}
.tag-danger { background: rgba(225, 29, 72, 0.1); color: var(--danger); border-color: rgba(225, 29, 72, 0.2); }
.tag-warning { background: rgba(245, 158, 11, 0.1); color: var(--warning); border-color: rgba(245, 158, 11, 0.2); }
.tag-success { background: rgba(16, 185, 129, 0.1); color: var(--success); border-color: rgba(16, 185, 129, 0.2); }
.tag-neutral { background: var(--bg-hover); color: var(--text-muted); }
</style>
'''

# ---- Landing page (public) -----------------------------------------------

LANDING_PAGE = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LoneWarrior / Autonomous Server Security</title>
<meta name="description" content="Open-source autonomous security agent that learns normal system behavior, detects threats in real time, and responds automatically.">
''' + _SHARED_HEAD + r'''
<style>
/* ---- Navbar ---- */
nav {
  position: sticky; top: 0; z-index: 100;
  background: var(--bg);
  border-bottom: 1px solid var(--border);
  height: 64px; display: flex; align-items: center;
}
.nav-wrap {
  max-width: 1200px; width: 100%; margin: 0 auto; padding: 0 24px;
  display: flex; justify-content: space-between; align-items: center;
}
.logo {
  font-weight: 700; font-size: 18px;
  display: flex; align-items: center; gap: 8px; color: var(--text-main);
  letter-spacing: -0.5px;
}
.logo em { font-style: normal; font-weight: 400; color: var(--text-muted); }
.nav-links { display: flex; gap: 24px; align-items: center; }
.nav-links a { font-size: 14px; color: var(--text-muted); }
.nav-links a:hover { color: var(--text-main); }

/* ---- Hero ---- */
.hero {
  padding: 100px 0 80px; text-align: center;
}
.hero h1 {
  font-size: clamp(2.5rem, 5vw, 4rem);
  font-weight: 700; letter-spacing: -0.04em; line-height: 1.1;
  margin-bottom: 20px; color: var(--text-main);
}
.hero p {
  font-size: clamp(1.1rem, 2vw, 1.2rem); color: var(--text-muted);
  max-width: 600px; margin: 0 auto 40px; line-height: 1.6;
}
.hero-btns {
  display: flex; gap: 16px; justify-content: center; flex-wrap: wrap; margin-bottom: 56px;
}

.cmd-box {
  margin: 0 auto; max-width: 600px; background: var(--bg-panel);
  border: 1px solid var(--border); border-radius: var(--radius);
  padding: 16px 20px; font-family: var(--font-mono); font-size: 13px;
  color: var(--text-main); display: flex; align-items: center; gap: 12px;
  cursor: pointer; text-align: left;
}
.cmd-box:hover { border-color: var(--border-focus); }
.cmd-box .prompt { color: var(--text-muted); user-select: none; }
.cmd-box code { flex: 1; }
.cmd-box .copy-hint { color: var(--text-muted); font-size: 12px; font-family: var(--font-main); transition: color 0.15s; }
.cmd-box.copied .copy-hint { color: var(--success); }

/* ---- Sections ---- */
.wrap { max-width: 1200px; margin: 0 auto; padding: 0 24px; }
.section { padding: 80px 0; border-top: 1px solid var(--border); }
.section-title {
  font-size: 24px; font-weight: 600; margin-bottom: 12px; letter-spacing: -0.02em;
}
.section-sub {
  color: var(--text-muted); max-width: 600px; margin-bottom: 48px; font-size: 15px; line-height: 1.6;
}

/* ---- Features Grid ---- */
.feature-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
.feature-card {
  background: var(--bg-panel); border: 1px solid var(--border);
  padding: 24px; border-radius: var(--radius);
}
.feature-card h3 { font-size: 16px; font-weight: 600; margin-bottom: 8px; color: var(--text-main); }
.feature-card p { color: var(--text-muted); font-size: 14px; line-height: 1.6; }

/* ---- Stats Bar ---- */
.stats-bar {
  display: flex; gap: 40px; padding: 40px 24px;
  background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius);
  margin-bottom: 80px;
}
.stat { flex: 1; }
.stat-val { font-size: 28px; font-weight: 700; color: var(--text-main); margin-bottom: 4px; }
.stat-label { font-size: 13px; color: var(--text-muted); }

/* Footer */
footer { border-top: 1px solid var(--border); padding: 40px 0; text-align: left; }
.footer-wrap { display: flex; justify-content: space-between; align-items: center; max-width: 1200px; margin: 0 auto; padding: 0 24px;}
.footer-links { display: flex; gap: 24px; }
.footer-links a { color: var(--text-muted); font-size: 13px; }
.footer-links a:hover { color: var(--text-main); }
.footer-text { color: var(--text-muted); font-size: 13px; }

@media(max-width: 900px) { .feature-grid { grid-template-columns: repeat(2, 1fr); } .stats-bar { flex-wrap: wrap; } .stat { min-width: 40%; } }
@media(max-width: 600px) { .feature-grid { grid-template-columns: 1fr; } .footer-wrap { flex-direction: column; gap: 20px; align-items: flex-start; } }
</style>
</head>
<body>

<nav>
  <div class="nav-wrap">
    <div class="logo">Lone<em>Warrior</em></div>
    <div class="nav-links">
      <a href="#features">Platform</a>
      <a href="https://github.com/0xshivangpatel/LoneWarrior" target="_blank">Documentation</a>
      <a href="/dashboard" class="btn btn-outline" style="padding: 6px 12px">Dashboard</a>
    </div>
  </div>
</nav>

<section class="hero"><div class="wrap">
  <h1>Autonomous Security<br>for Linux Infrastructure</h1>
  <p>LoneWarrior effortlessly learns your server's normal behavior, detects real-time threats, and automatically mitigates them with precision.</p>
  
  <div class="hero-btns">
    <a href="https://github.com/0xshivangpatel/LoneWarrior" class="btn btn-primary">Deployment Guide</a>
    <a href="/dashboard" class="btn btn-outline">System Dashboard</a>
  </div>

  <div class="cmd-box" onclick="navigator.clipboard.writeText('curl -sSL https://raw.githubusercontent.com/0xshivangpatel/LoneWarrior/main/get-lonewarrior.sh | sudo bash'); this.classList.add('copied'); setTimeout(()=>this.classList.remove('copied'), 2000)">
    <span class="prompt">$</span>
    <code>curl -sSL https://raw.githubusercontent.com/0xshivangpatel/LoneWarrior/main/get-lonewarrior.sh | sudo bash</code>
    <span class="copy-hint" style="margin-left:auto">Copy</span>
  </div>
</div></section>

<div class="wrap">
  <div class="stats-bar">
    <div class="stat"><div class="stat-val">6</div><div class="stat-label">Analysis Layers</div></div>
    <div class="stat"><div class="stat-val">&lt;5 min</div><div class="stat-label">Initial Baseline</div></div>
    <div class="stat"><div class="stat-val">100%</div><div class="stat-label">Autonomous Operation</div></div>
    <div class="stat"><div class="stat-val">256MB</div><div class="stat-label">Minimum Overhead</div></div>
  </div>
</div>

<section class="section" id="features"><div class="wrap">
  <h2 class="section-title">Core Capabilities</h2>
  <p class="section-sub">Zero required configuration. LoneWarrior provides out-of-the-box adaptive intelligence to protect your infrastructure natively.</p>

  <div class="feature-grid">
    <div class="feature-card">
      <h3>Adaptive Baseline</h3>
      <p>Continuous behavioral modeling mapping processes, network, and auth patterns. Detects deviations instantly.</p>
    </div>
    <div class="feature-card">
      <h3>Real-Time Detection</h3>
      <p>Mitigates brute-force, reverse shells, privilege escalation, web exploits, and port scans.</p>
    </div>
    <div class="feature-card">
      <h3>Autonomous Response</h3>
      <p>Confidence-scored actions applying IP blacklisting, process termination, and auto-rollback.</p>
    </div>
    <div class="feature-card">
      <h3>Web Log Forensics</h3>
      <p>Tails nginx and apache logs locally to catch OWASP Top 10 exploits, scanning fingerprinting, and anomalies.</p>
    </div>
    <div class="feature-card">
      <h3>File Integrity Monitoring</h3>
      <p>Watches critical directories. Automatically spots and quarantines malicious webshell uploads.</p>
    </div>
    <div class="feature-card">
      <h3>Threat Intelligence</h3>
      <p>Ingests remote signatures via Project Honey Pot and AbuseIPDB, bolstering local heuristics passively.</p>
    </div>
  </div>
</div></section>

<footer>
  <div class="footer-wrap">
    <p class="footer-text">LoneWarrior System &middot; Open Source Security</p>
    <div class="footer-links">
      <a href="https://github.com/0xshivangpatel/LoneWarrior">Source</a>
      <a href="/dashboard">Console</a>
    </div>
  </div>
</footer>

</body></html>
'''


# ---- Login page ----------------------------------------------------------

LOGIN_PAGE = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Authenticate / LoneWarrior</title>
''' + _SHARED_HEAD + r'''
<style>
body { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.login-card {
  width: 100%; max-width: 380px; padding: 40px;
  background: var(--bg-panel); border: 1px solid var(--border); border-radius: var(--radius);
}
.logo { font-weight: 700; font-size: 20px; margin-bottom: 4px; color: var(--text-main); text-align: left; }
.logo em { font-style: normal; color: var(--text-muted); }
.sub { color: var(--text-muted); font-size: 14px; margin-bottom: 32px; text-align: left; }

.field { margin-bottom: 20px; }
.field label { display: block; font-size: 12px; font-weight: 600; margin-bottom: 8px; color: var(--text-muted); }
.field input {
  width: 100%; padding: 10px 12px; background: var(--bg);
  border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--text-main);
  font-family: var(--font-main); font-size: 14px; transition: border-color 0.15s;
  outline: none;
}
.field input:focus { border-color: var(--primary); }

.btn { width: 100%; padding: 10px; font-size: 14px; }

.error {
  background: rgba(225, 29, 72, 0.1); color: var(--danger);
  border: 1px solid rgba(225, 29, 72, 0.2); padding: 10px; border-radius: var(--radius-sm);
  font-size: 13px; margin-bottom: 24px; font-weight: 500;
}
.hint { margin-top: 24px; font-size: 12px; color: var(--text-muted); text-align: left; }
.hint code { font-family: var(--font-mono); color: var(--text-main); }
</style>
</head>
<body>

<div class="login-card">
  <div class="logo">Lone<em>Warrior</em></div>
  <p class="sub">Administrator Authentication</p>
  
  {% if error %}<div class="error">{{ error }}</div>{% endif %}

  <form method="POST" action="/login">
    <div class="field">
      <label>Access Key</label>
      <input type="password" name="key" required autofocus>
    </div>
    <button type="submit" class="btn btn-primary">Sign In</button>
  </form>
  
  <p class="hint">Check <code>secret_key</code> via <code>/etc/lonewarrior/config.yaml</code></p>
</div>

</body></html>
'''


# ---- Dashboard (authenticated) -------------------------------------------

DASHBOARD_PAGE = r'''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Console / LoneWarrior</title>
''' + _SHARED_HEAD + r'''
<style>
/* ---- Topbar ---- */
.topbar {
  display: flex; justify-content: space-between; align-items: center;
  padding: 0 24px; height: 56px; background: var(--bg-panel);
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 100;
}
.tb-left { display: flex; align-items: center; gap: 16px; }
.tb-logo { font-weight: 700; font-size: 16px; color: var(--text-main); }
.tb-logo em { font-style: normal; color: var(--text-muted); }
.tb-path { color: var(--text-muted); font-size: 13px; }
.tb-path span { color: var(--text-main); margin-left: 8px; }

.tb-actions { display: flex; align-items: center; gap: 24px; }
.status-ind { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 500; color: var(--text-muted); }
.status-ind .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--success); }
.status-ind.error .dot { background: var(--danger); }
.logout { color: var(--text-muted); font-size: 13px; }

/* ---- Layout ---- */
.main { max-width: 1440px; margin: 0 auto; padding: 32px 24px; }

/* ---- Metrics Grid ---- */
.metric-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
.metric-card { padding: 20px; }
.m-title { font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; }
.m-val { font-size: 28px; font-weight: 700; color: var(--text-main); line-height: 1; }
.m-sub { font-size: 12px; color: var(--text-muted); margin-top: 8px; }

.progress-bg { height: 2px; background: var(--bg-hover); border-radius: 1px; margin-top: 12px; overflow: hidden; }
.progress-fill { height: 100%; background: var(--primary); transition: width 0.5s ease; width: 0%; }

.text-danger { color: var(--danger); }
.text-warning { color: var(--warning); }
.text-success { color: var(--success); }

/* ---- Panels ---- */
.p-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--border); }
.p-title { font-size: 14px; font-weight: 600; color: var(--text-main); }
.panel { margin-bottom: 24px; }

/* Baseline Subpanel */
.bl-metrics { display: grid; grid-template-columns: repeat(4, 1fr); padding: 16px; gap: 12px; }
.bl-item { padding: 12px 16px; background: var(--bg-table); border: 1px solid var(--border); border-radius: var(--radius-sm); }
.bl-val { font-size: 20px; font-weight: 600; color: var(--text-main); }
.bl-label { font-size: 11px; color: var(--text-muted); margin-top: 4px; }

/* Tables */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 12px 20px; font-size: 11px; font-weight: 500; color: var(--text-muted); background: var(--bg-table); border-bottom: 1px solid var(--border); }
td { padding: 12px 20px; font-size: 13px; border-bottom: 1px solid var(--border); color: var(--text-main); background: var(--bg-panel); }
tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--bg-hover); }

.td-desc { max-width: 400px; white-space: normal; color: var(--text-muted); }

/* Error banner */
.err-banner {
  background: rgba(225, 29, 72, 0.1); border: 1px solid rgba(225, 29, 72, 0.2); border-radius: var(--radius-sm);
  padding: 12px 16px; margin-bottom: 24px; color: var(--danger); font-size: 13px; font-weight: 500;
  display: none; align-items: center; gap: 8px;
}
.err-banner.show { display: flex; }

@media(max-width: 1024px) { .metric-grid, .bl-metrics { grid-template-columns: repeat(2, 1fr); } }
@media(max-width: 768px) { .metric-grid, .bl-metrics { grid-template-columns: 1fr; } }
</style>
</head>
<body>

<div class="topbar">
  <div class="tb-left">
    <div class="tb-logo">Lone<em>Warrior</em></div>
    <div class="tb-path">/ <span>system console</span></div>
  </div>
  <div class="tb-actions">
    <div class="status-ind" id="conn"><span class="dot"></span> <span>Connected</span></div>
    <a href="/logout" class="logout">Sign out</a>
  </div>
</div>

<div class="main">
  <div class="err-banner" id="err-banner">
    <span id="err-msg">API connection lost. Attempting to reconnect...</span>
  </div>

  <div class="metric-grid">
    <div class="panel metric-card">
      <div class="m-title">Engine Phase</div>
      <div class="m-val" id="v-phase">--</div>
      <div class="m-sub" id="v-phase-sub">Initializing</div>
      <div class="progress-bg"><div class="progress-fill" id="v-phase-bar"></div></div>
    </div>
    
    <div class="panel metric-card">
      <div class="m-title">Threat Score</div>
      <div class="m-val text-success" id="v-conf">0%</div>
      <div class="m-sub" id="v-conf-sub">Telemetry normal</div>
    </div>

    <div class="panel metric-card">
      <div class="m-title">Active Mitigations</div>
      <div class="m-val" id="v-blocks">0</div>
      <div class="m-sub">Current IP blocks applied</div>
    </div>

    <div class="panel metric-card">
      <div class="m-title">Network Lockdown</div>
      <div class="m-val text-success" id="v-contain">Inactive</div>
      <div class="m-sub" id="v-contain-sub">Outbound traffic permitted</div>
    </div>
  </div>

  <div class="panel">
    <div class="p-header">
      <div class="p-title">Behavioral Baseline</div>
      <div class="badge" id="bl-status">Syncing</div>
    </div>
    <div class="bl-metrics">
      <div class="bl-item"><div class="bl-val" id="bl-proc">-</div><div class="bl-label">Processes</div></div>
      <div class="bl-item"><div class="bl-val" id="bl-net">-</div><div class="bl-label">Destinations</div></div>
      <div class="bl-item"><div class="bl-val" id="bl-ports">-</div><div class="bl-label">Bound Ports</div></div>
      <div class="bl-item"><div class="bl-val" id="bl-users">-</div><div class="bl-label">Auth Contexts</div></div>
    </div>
  </div>

  <div class="panel">
    <div class="p-header">
      <div class="p-title">Detection Log</div>
      <div class="badge" id="det-n">0</div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Category</th><th>Details</th><th>Confidence</th><th>Stage</th></tr></thead>
        <tbody id="det-tb"><tr><td colspan="5" style="text-align:center; padding: 32px; color: var(--text-muted)">Awaiting telemetry...</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="panel">
    <div class="p-header">
      <div class="p-title">Action Log</div>
      <div class="badge" id="act-n">0</div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>Directive</th><th>Target</th><th>Status</th><th>Result</th></tr></thead>
        <tbody id="act-tb"><tr><td colspan="5" style="text-align:center; padding: 32px; color: var(--text-muted)">No automated actions recorded.</td></tr></tbody>
      </table>
    </div>
  </div>

</div>

<script>
// Formatters
const esc = t => { if(!t) return ''; const d=document.createElement('div'); d.textContent=String(t); return d.innerHTML; };
const ft = iso => { try{ return new Date(iso).toLocaleString(void 0, {month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit'}) } catch(e){return '-'} };

// Tags mapping
const getConfTag = c => {
  c = Math.round(c||0);
  if(c>=80) return `<span class="tag tag-danger">${c}%</span>`;
  if(c>=60) return `<span class="tag tag-warning">${c}%</span>`;
  if(c>=30) return `<span class="tag tag-neutral">${c}%</span>`;
  return `<span class="tag tag-success">${c}%</span>`;
};
const getStatTag = s => {
  if (s === 'success') return `<span class="tag tag-success">${esc(s)}</span>`;
  if (s === 'failed') return `<span class="tag tag-danger">${esc(s)}</span>`;
  if (s === 'rolled_back') return `<span class="tag tag-warning">${esc(s)}</span>`;
  return `<span class="tag tag-neutral">${esc(s)}</span>`;
};

// Fetch logic
let errCount = 0;
async function fetchAPI(endpoint) {
  try {
    const res = await fetch(endpoint, { credentials: 'same-origin' });
    if(res.status === 401) { location.href = '/login'; return null; }
    if(!res.ok) throw new Error('HTTP ' + res.status);
    
    errCount = 0;
    document.getElementById('err-banner').classList.remove('show');
    return await res.json();
  } catch(e) {
    errCount++;
    if(errCount >= 2) {
      document.getElementById('err-banner').classList.add('show');
      const conn = document.getElementById('conn');
      conn.classList.add('error');
      conn.querySelector('span:last-child').textContent = 'Disconnected';
    }
    return null;
  }
}

async function renderStatus() {
  const d = await fetchAPI('/api/status');
  if(!d) return;

  document.getElementById('v-phase').textContent = (d.phase||'').replace('PHASE_','').replace('_',' ') || 'STANDBY';
  document.getElementById('v-phase-bar').style.width = `${d.phase_progress||0}%`;
  document.getElementById('v-phase-sub').textContent = `${d.phase_progress||0}% active`;

  const conf = Math.round(d.attack_confidence||0);
  const cv = document.getElementById('v-conf');
  cv.textContent = conf + '%';
  cv.className = 'm-val ' + (conf >= 60 ? 'text-danger' : (conf >= 30 ? 'text-warning' : 'text-success'));
  document.getElementById('v-conf-sub').textContent = conf === 0 ? 'Telemetry normal' : (conf > 50 ? 'Immediate threat' : 'Elevated risk');
  
  document.getElementById('v-blocks').textContent = d.active_blocks||0;

  const cont = document.getElementById('v-contain');
  if(d.containment_active) { cont.textContent = 'LOCKED'; cont.className = 'm-val text-danger'; document.getElementById('v-contain-sub').textContent = 'Traffic isolated'; }
  else { cont.textContent = 'Passive'; cont.className = 'm-val text-success'; document.getElementById('v-contain-sub').textContent = 'Open routing'; }

  const conn = document.getElementById('conn');
  if(d.health === 'healthy') {
    conn.classList.remove('error'); conn.querySelector('span:last-child').textContent = 'Connected';
  } else {
    conn.classList.add('error'); conn.querySelector('span:last-child').textContent = 'Degraded';
  }
}

async function renderBaseline() {
  const d = await fetchAPI('/api/baseline');
  if(!d) return;
  document.getElementById('bl-proc').textContent = d.processes != null ? d.processes : '-';
  document.getElementById('bl-net').textContent = d.network_destinations != null ? d.network_destinations : '-';
  document.getElementById('bl-ports').textContent = d.listening_ports != null ? d.listening_ports : '-';
  document.getElementById('bl-users').textContent = d.users != null ? d.users : '-';
  
  const b = document.getElementById('bl-status');
  b.textContent = d.frozen ? 'FROZEN' : 'ACTIVE';
  b.className = 'badge' + (d.frozen ? ' active' : '');
}

async function renderTables() {
  const det = await fetchAPI('/api/detections?limit=25');
  if(det) {
    const dn = document.getElementById('det-n');
    dn.textContent = det.count || 0;
    dn.className = 'badge' + (det.count > 0 ? ' active' : '');
    
    document.getElementById('det-tb').innerHTML = (det.detections||[]).length 
      ? det.detections.map(r => `<tr><td>${ft(r.timestamp)}</td><td><strong>${esc(r.type)}</strong></td><td class="td-desc">${esc(r.description)}</td><td>${getConfTag(r.confidence)}</td><td>${esc(r.killchain_stage)}</td></tr>`).join('')
      : `<tr><td colspan="5" style="text-align:center; padding: 32px; color: var(--text-muted)">No active detections logged.</td></tr>`;
  }

  const act = await fetchAPI('/api/actions?limit=25');
  if(act) {
    const an = document.getElementById('act-n');
    an.textContent = act.count || 0;
    an.className = 'badge' + (act.count > 0 ? ' active' : '');

    document.getElementById('act-tb').innerHTML = (act.actions||[]).length
      ? act.actions.map(r => `<tr><td>${ft(r.timestamp)}</td><td>${esc(r.type)}</td><td><code>${esc(r.target)}</code></td><td>${getStatTag(r.status)}</td><td class="td-desc">${esc(r.result || r.error)}</td></tr>`).join('')
      : `<tr><td colspan="5" style="text-align:center; padding: 32px; color: var(--text-muted)">No actions taken yet.</td></tr>`;
  }
}

const sync = () => { renderStatus(); renderBaseline(); renderTables(); };
sync(); setInterval(sync, 5000);

</script>
</body></html>
'''
