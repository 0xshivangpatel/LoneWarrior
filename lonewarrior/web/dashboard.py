"""
LoneWarrior Web Dashboard
Real-time monitoring and management interface
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone, timedelta
from pathlib import Path
import json

try:
    from flask import Flask, render_template, jsonify, request, Response
    from flask import render_template_string
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

logger = logging.getLogger(__name__)


class WebDashboard:
    """
    Web dashboard for LoneWarrior monitoring and management.
    
    Provides:
    - Real-time status monitoring
    - Detection timeline
    - Action history
    - Configuration viewer
    """
    
    def __init__(self, config: Dict[str, Any], database, event_bus, state_manager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        self.enabled = config.get('web_dashboard', {}).get('enabled', False)
        self.port = config.get('web_dashboard', {}).get('port', 5000)
        self.bind_address = config.get('web_dashboard', {}).get('bind_address', '127.0.0.1')
        
        self.app = None
        self._thread = None
        
    def start(self):
        """Start web dashboard"""
        if not self.enabled:
            logger.info("Web dashboard disabled in config")
            return
            
        if not FLASK_AVAILABLE:
            logger.warning("Flask not installed. Run: pip install flask")
            return
        
        self._create_app()
        self._start_server()
        logger.info(f"Web dashboard started at http://{self.bind_address}:{self.port}")
    
    def stop(self):
        """Stop web dashboard"""
        if self._thread and self._thread.is_alive():
            # Flask doesn't have clean shutdown, but the daemon thread will die with main
            pass
        logger.info("Web dashboard stopped")
    
    def _create_app(self):
        """Create Flask application"""
        self.app = Flask(__name__)
        self.app.config['JSON_SORT_KEYS'] = False
        
        # Routes
        @self.app.route('/')
        def index():
            return render_template_string(DASHBOARD_TEMPLATE, 
                                         port=self.port)
        
        @self.app.route('/api/status')
        def api_status():
            return jsonify(self._get_status())
        
        @self.app.route('/api/detections')
        def api_detections():
            limit = request.args.get('limit', 50, type=int)
            # Bound limit to prevent resource abuse
            limit = max(1, min(limit, 100))
            return jsonify(self._get_detections(limit))
        
        @self.app.route('/api/actions')
        def api_actions():
            limit = request.args.get('limit', 50, type=int)
            # Bound limit to prevent resource abuse
            limit = max(1, min(limit, 100))
            return jsonify(self._get_actions(limit))
        
        @self.app.route('/api/baseline')
        def api_baseline():
            return jsonify(self._get_baseline_summary())
        
        @self.app.route('/api/health')
        def api_health():
            return jsonify({'status': 'healthy', 'timestamp': datetime.now(timezone.utc).isoformat()})
        
        @self.app.route('/api/events/stream')
        def event_stream():
            """Server-sent events for real-time updates"""
            def generate():
                # Simple polling-based SSE
                import time
                while True:
                    data = json.dumps(self._get_status())
                    yield f"data: {data}\n\n"
                    time.sleep(5)
            return Response(generate(), mimetype='text/event-stream')
    
    def _start_server(self):
        """Start Flask server in background thread"""
        import threading
        
        def run():
            # Disable Flask's default logging
            import logging as flask_logging
            flask_logging.getLogger('werkzeug').setLevel(flask_logging.WARNING)
            
            self.app.run(
                host=self.bind_address,
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True
            )
        
        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
    
    def _get_status(self) -> Dict[str, Any]:
        """Get current system status"""
        try:
            state = self.state.get_state_summary()
            return {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'phase': state.get('phase', 'Unknown'),
                'phase_progress': state.get('phase_progress', 0),
                'attack_confidence': state.get('attack_confidence', 0),
                'containment_active': state.get('containment_active', False),
                'baseline_frozen': state.get('baseline_frozen', False),
                'active_blocks': len(state.get('active_blocks', [])),
                'uptime': self._get_uptime(),
                'health': 'healthy'
            }
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return {'health': 'error', 'error': str(e)}
    
    def _get_detections(self, limit: int = 50) -> Dict[str, Any]:
        """Get recent detections"""
        try:
            detections = self.db.get_recent_detections(limit=limit)
            return {
                'count': len(detections),
                'detections': [
                    {
                        'id': d.id,
                        'type': d.detection_type,
                        'description': d.description,
                        'confidence': d.confidence_score,
                        'killchain_stage': d.killchain_stage,
                        'timestamp': d.detected_at.isoformat() if d.detected_at else None,
                        'resolved': d.resolved
                    }
                    for d in detections
                ]
            }
        except Exception as e:
            logger.error(f"Error getting detections: {e}")
            return {'count': 0, 'detections': [], 'error': str(e)}
    
    def _get_actions(self, limit: int = 50) -> Dict[str, Any]:
        """Get recent actions"""
        try:
            actions = self.db.get_recent_actions(limit=limit)
            return {
                'count': len(actions),
                'actions': [
                    {
                        'id': a.id,
                        'type': a.action_type,
                        'status': a.status,
                        'target': a.target,
                        'result': a.result,
                        'error': a.error,
                        'timestamp': a.executed_at.isoformat() if a.executed_at else None
                    }
                    for a in actions
                ]
            }
        except Exception as e:
            logger.error(f"Error getting actions: {e}")
            return {'count': 0, 'actions': [], 'error': str(e)}
    
    def _get_baseline_summary(self) -> Dict[str, Any]:
        """Get baseline summary"""
        try:
            return {
                'processes': self.state.get_baseline_count('processes'),
                'network_destinations': self.state.get_baseline_count('network'),
                'listening_ports': self.state.get_baseline_count('ports'),
                'users': self.state.get_baseline_count('users'),
                'frozen': self.state.is_baseline_frozen()
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_uptime(self) -> str:
        """Get service uptime"""
        try:
            import subprocess
            result = subprocess.run(
                ['systemctl', 'show', 'lonewarrior', '--property=ActiveEnterTimestamp'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                # Parse timestamp and calculate uptime
                return result.stdout.strip().split('=')[1] if '=' in result.stdout else 'Unknown'
        except Exception:
            pass
        return 'Unknown'


# HTML Template (embedded for simplicity)
DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LoneWarrior Dashboard</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
            --border-color: #30363d;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }
        
        .logo {
            font-size: 24px;
            font-weight: 700;
            color: var(--accent-blue);
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-healthy { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); }
        .status-warning { background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); }
        .status-critical { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .card-title {
            font-size: 14px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .card-value {
            font-size: 32px;
            font-weight: 700;
            color: var(--text-primary);
        }
        
        .card-value.green { color: var(--accent-green); }
        .card-value.red { color: var(--accent-red); }
        .card-value.yellow { color: var(--accent-yellow); }
        
        .progress-bar {
            height: 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-green));
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .table-container {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 20px;
        }
        
        .table-header {
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            text-align: left;
            padding: 12px 20px;
            border-bottom: 1px solid var(--border-color);
        }
        
        th {
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        tr:last-child td { border-bottom: none; }
        tr:hover { background: var(--bg-tertiary); }
        
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }
        
        .badge-high { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }
        .badge-medium { background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); }
        .badge-low { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); }
        .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); }
        .badge-failed { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); }
        
        .refresh-note {
            text-align: center;
            color: var(--text-secondary);
            font-size: 12px;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">🛡️ LoneWarrior</div>
            <div id="health-badge" class="status-badge status-healthy">Healthy</div>
        </header>
        
        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Current Phase</span>
                </div>
                <div id="phase" class="card-value">Loading...</div>
                <div class="progress-bar">
                    <div id="phase-progress" class="progress-fill" style="width: 0%"></div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Attack Confidence</span>
                </div>
                <div id="attack-confidence" class="card-value">0%</div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Active Blocks</span>
                </div>
                <div id="active-blocks" class="card-value">0</div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Containment</span>
                </div>
                <div id="containment" class="card-value green">Inactive</div>
            </div>
        </div>
        
        <div class="table-container">
            <div class="table-header">Recent Detections</div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Description</th>
                        <th>Confidence</th>
                        <th>Stage</th>
                    </tr>
                </thead>
                <tbody id="detections-body">
                    <tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="table-container">
            <div class="table-header">Recent Actions</div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody id="actions-body">
                    <tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="refresh-note">Auto-refreshes every 5 seconds</div>
    </div>
    
    <script>
        // XSS prevention: escape HTML entities
        function escapeHtml(text) {
            if (text === null || text === undefined) return '';
            const div = document.createElement('div');
            div.textContent = String(text);
            return div.innerHTML;
        }
        
        function formatTime(isoStr) {
            if (!isoStr) return '-';
            const d = new Date(isoStr);
            return d.toLocaleTimeString();
        }
        
        function getConfidenceBadge(conf) {
            // conf is a number, safe to use directly
            if (conf >= 70) return '<span class="badge badge-high">High</span>';
            if (conf >= 40) return '<span class="badge badge-medium">Medium</span>';
            return '<span class="badge badge-low">Low</span>';
        }
        
        function getStatusBadge(status) {
            // Whitelist known status values to prevent XSS
            const safeStatuses = {
                'success': '<span class="badge badge-success">Success</span>',
                'failed': '<span class="badge badge-failed">Failed</span>',
                'executing': '<span class="badge">Executing</span>',
                'pending': '<span class="badge">Pending</span>',
                'rolled_back': '<span class="badge">Rolled Back</span>'
            };
            return safeStatuses[status] || '<span class="badge">' + escapeHtml(status) + '</span>';
        }
        
        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                document.getElementById('phase').textContent = data.phase || 'Unknown';
                document.getElementById('phase-progress').style.width = (data.phase_progress || 0) + '%';
                
                const confEl = document.getElementById('attack-confidence');
                confEl.textContent = Math.round(data.attack_confidence || 0) + '%';
                confEl.className = 'card-value ' + (data.attack_confidence > 50 ? 'red' : data.attack_confidence > 20 ? 'yellow' : 'green');
                
                document.getElementById('active-blocks').textContent = data.active_blocks || 0;
                
                const contEl = document.getElementById('containment');
                contEl.textContent = data.containment_active ? 'ACTIVE' : 'Inactive';
                contEl.className = 'card-value ' + (data.containment_active ? 'red' : 'green');
                
                const healthBadge = document.getElementById('health-badge');
                healthBadge.textContent = data.health === 'healthy' ? 'Healthy' : 'Error';
                healthBadge.className = 'status-badge ' + (data.health === 'healthy' ? 'status-healthy' : 'status-critical');
            } catch (e) {
                console.error('Status fetch error:', e);
            }
        }
        
        async function fetchDetections() {
            try {
                const res = await fetch('/api/detections?limit=10');
                const data = await res.json();
                
                const tbody = document.getElementById('detections-body');
                if (data.detections && data.detections.length > 0) {
                    tbody.innerHTML = data.detections.map(d => `
                        <tr>
                            <td>${escapeHtml(formatTime(d.timestamp))}</td>
                            <td>${escapeHtml(d.type)}</td>
                            <td>${escapeHtml(d.description) || '-'}</td>
                            <td>${getConfidenceBadge(d.confidence)}</td>
                            <td>${escapeHtml(d.killchain_stage) || '-'}</td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">No detections</td></tr>';
                }
            } catch (e) {
                console.error('Detections fetch error:', e);
            }
        }
        
        async function fetchActions() {
            try {
                const res = await fetch('/api/actions?limit=10');
                const data = await res.json();
                
                const tbody = document.getElementById('actions-body');
                if (data.actions && data.actions.length > 0) {
                    tbody.innerHTML = data.actions.map(a => `
                        <tr>
                            <td>${escapeHtml(formatTime(a.timestamp))}</td>
                            <td>${escapeHtml(a.type)}</td>
                            <td>${escapeHtml(a.target) || '-'}</td>
                            <td>${getStatusBadge(a.status)}</td>
                            <td>${escapeHtml(a.result || a.error) || '-'}</td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-secondary)">No actions</td></tr>';
                }
            } catch (e) {
                console.error('Actions fetch error:', e);
            }
        }
        
        function refreshAll() {
            fetchStatus();
            fetchDetections();
            fetchActions();
        }
        
        // Initial load
        refreshAll();
        
        // Auto-refresh every 5 seconds
        setInterval(refreshAll, 5000);
    </script>
</body>
</html>
'''
