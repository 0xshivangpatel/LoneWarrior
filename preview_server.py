"""
Lightweight preview server for testing LoneWarrior web pages.
Serves the landing page + dashboard with mock data (no real LoneWarrior engine needed).

Usage:
    pip install flask flask-cors
    python preview_server.py

Then open http://localhost:5555/ in your browser.
Login key: preview-key-123
"""
import json
import time
import random
import hashlib
import hmac as hmac_mod
import secrets
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Flask, jsonify, request, Response, redirect,
    render_template_string, make_response
)
from flask_cors import CORS

# Import the HTML templates from the real dashboard module
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lonewarrior.web.dashboard import LANDING_PAGE, LOGIN_PAGE, DASHBOARD_PAGE

app = Flask(__name__)
CORS(app)

# Preview secret key
SECRET_KEY = "preview-key-123"

def generate_token():
    expires = int(time.time()) + 86400
    payload = f"{expires}"
    sig = hmac_mod.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{expires}.{sig}"

def verify_token(token):
    if not token:
        return False
    try:
        expires_str, sig = token.split(".", 1)
        if time.time() > int(expires_str):
            return False
        expected = hmac_mod.new(SECRET_KEY.encode(), expires_str.encode(), hashlib.sha256).hexdigest()[:32]
        return hmac_mod.compare_digest(sig, expected)
    except Exception:
        return False

def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        token = request.cookies.get("lw_token") or request.headers.get("X-LW-Token", "")
        if not verify_token(token):
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect("/login")
        return fn(*a, **kw)
    return wrapper


# ---- Routes ----

@app.route("/")
def landing():
    return render_template_string(LANDING_PAGE)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)
    key = request.form.get("key", "").strip()
    if key == SECRET_KEY:
        token = generate_token()
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("lw_token", token, httponly=True, samesite="Strict", max_age=86400)
        return resp
    return render_template_string(LOGIN_PAGE, error="Invalid access key")

@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("lw_token")
    return resp

@app.route("/dashboard")
@require_auth
def dashboard():
    return render_template_string(DASHBOARD_PAGE)


# ---- Mock API ----

PHASES = ["PHASE_0_INSTANT", "PHASE_1_FAST", "PHASE_2_EXPANDED", "PHASE_3_CONTINUOUS"]

@app.route("/api/status")
@require_auth
def api_status():
    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "PHASE_2_EXPANDED",
        "phase_progress": 67,
        "attack_confidence": 23,
        "containment_active": False,
        "baseline_frozen": False,
        "active_blocks": 3,
        "uptime": "2 days, 14:32:07",
        "health": "healthy",
    })

@app.route("/api/detections")
@require_auth
def api_detections():
    types = ["brute_force", "sql_injection", "xss_attack", "port_scan", "path_traversal", "reverse_shell"]
    descs = [
        "SSH brute force from 203.0.113.5 (42 failed attempts in 2 min)",
        "SQL Injection attempt: UNION SELECT on /search?q=",
        "XSS payload detected in /page?name=<script>",
        "Port scan from 198.51.100.22 (137 ports in 10s)",
        "Path traversal attempt: ../../../../etc/passwd",
        "Suspicious outbound connection to known C2 IP 45.33.32.156",
        "Scanner detected: sqlmap/1.5 user-agent",
        "Rapid 404 scanning from 192.0.2.100 (89 requests in 30s)",
    ]
    dets = []
    for i in range(min(request.args.get("limit", 10, type=int), 20)):
        dets.append({
            "id": 100 + i,
            "type": random.choice(types),
            "description": descs[i % len(descs)],
            "confidence": random.randint(25, 95),
            "killchain_stage": random.choice(["reconnaissance", "weaponization", "delivery", "exploitation", "installation"]),
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=i * 7 + random.randint(0, 5))).isoformat(),
            "resolved": random.choice([True, False]),
        })
    return jsonify({"count": len(dets), "detections": dets})

@app.route("/api/actions")
@require_auth
def api_actions():
    action_types = ["ip_block", "process_kill", "containment_enable", "ip_unblock"]
    statuses = ["success", "success", "success", "rolled_back", "failed"]
    acts = []
    for i in range(min(request.args.get("limit", 10, type=int), 20)):
        t = random.choice(action_types)
        s = random.choice(statuses)
        acts.append({
            "id": 200 + i,
            "type": t,
            "target": f"{random.randint(100,220)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "status": s,
            "result": f"Blocked for 3600s" if s == "success" and t == "ip_block" else ("Process terminated" if t == "process_kill" else ""),
            "error": "Health check failed — rolled back" if s == "rolled_back" else ("iptables timeout" if s == "failed" else None),
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=i * 12 + random.randint(0, 8))).isoformat(),
        })
    return jsonify({"count": len(acts), "actions": acts})

@app.route("/api/health")
def api_health():
    return jsonify({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})

@app.route("/api/baseline")
@require_auth
def api_baseline():
    return jsonify({
        "processes": 127,
        "network_destinations": 43,
        "listening_ports": 8,
        "users": 5,
        "frozen": False,
    })


if __name__ == "__main__":
    print()
    print("  +--------------------------------------------+")
    print("  |    LoneWarrior Preview Server               |")
    print("  +--------------------------------------------+")
    print(f"  |  Landing:   http://localhost:5556/          |")
    print(f"  |  Dashboard: http://localhost:5556/dashboard |")
    print(f"  |  Login key: {SECRET_KEY}           |")
    print("  +--------------------------------------------+")
    print()
    app.run(host="127.0.0.1", port=5556, debug=False)
