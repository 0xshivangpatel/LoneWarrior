"""
SQLite database management for LoneWarrior

Security Note:
- Database files are created with 0600 permissions (owner read/write only)
- Parent directories are created with 0700 permissions
- This prevents unauthorized access to security event data
"""

import os
import stat
import sqlite3
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from datetime import datetime, timezone

from lonewarrior.storage.models import (
    Event, Detection, Action, Baseline, Snapshot, ThreatIntel
)


logger = logging.getLogger(__name__)

# Secure file permissions
DB_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0600 - owner read/write only
DB_DIR_MODE = stat.S_IRWXU  # 0700 - owner full access only


class Database:
    """SQLite database manager with secure file permissions"""

    def __init__(self, db_path: str):
        """
        Initialize database with secure permissions

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)

        # Create parent directory with secure permissions
        self._create_secure_directory(self.db_path.parent)

        # Initialize database schema
        self._init_schema()

        # Ensure database file has secure permissions
        self._secure_database_file()

        logger.info(f"Database initialized at: {self.db_path}")

    def _create_secure_directory(self, dir_path: Path):
        """
        Create directory with secure permissions (0700)

        Args:
            dir_path: Directory path to create
        """
        if not dir_path.exists():
            # Create with restrictive umask
            old_umask = os.umask(0o077)
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
            finally:
                os.umask(old_umask)

        # Ensure correct permissions even if directory existed
        try:
            os.chmod(dir_path, DB_DIR_MODE)
        except OSError as e:
            logger.warning(f"Could not set directory permissions on {dir_path}: {e}")

    def _secure_database_file(self):
        """Set secure permissions on database file (0600)"""
        if self.db_path.exists():
            try:
                os.chmod(self.db_path, DB_FILE_MODE)
                logger.debug(f"Set secure permissions (0600) on {self.db_path}")
            except OSError as e:
                logger.warning(f"Could not set file permissions on {self.db_path}: {e}")
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections
        
        Yields:
            SQLite connection with row factory
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _init_schema(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    data TEXT NOT NULL,
                    baseline_phase INTEGER DEFAULT 0
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)')
            
            # Integration events table (Wazuh, ModSec, Suricata)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS integration_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT,
                    data TEXT NOT NULL,
                    processed BOOLEAN DEFAULT 0
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_integration_timestamp ON integration_events(timestamp)')
            
            # Detections table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    detection_type TEXT NOT NULL,
                    description TEXT,
                    confidence_score REAL NOT NULL,
                    event_ids TEXT,
                    data TEXT,
                    killchain_stage TEXT,
                    baseline_frozen BOOLEAN DEFAULT 0
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_score ON detections(confidence_score)')
            
            # Actions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    detection_id INTEGER,
                    target TEXT NOT NULL,
                    parameters TEXT,
                    snapshot_id INTEGER,
                    result TEXT,
                    error TEXT,
                    completed_at TEXT,
                    rolled_back BOOLEAN DEFAULT 0,
                    user_feedback TEXT,
                    FOREIGN KEY (detection_id) REFERENCES detections(id),
                    FOREIGN KEY (snapshot_id) REFERENCES snapshots(id)
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_actions_timestamp ON actions(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status)')
            
            # Baselines table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    baseline_type TEXT NOT NULL,
                    phase INTEGER NOT NULL,
                    key TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    observation_count INTEGER DEFAULT 1,
                    last_seen TEXT NOT NULL,
                    version INTEGER DEFAULT 1
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_baselines_type_key ON baselines(baseline_type, key)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_baselines_phase ON baselines(phase)')
            
            # Snapshots table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    snapshot_type TEXT NOT NULL,
                    state_data TEXT NOT NULL
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON snapshots(timestamp)')
            
            # Threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    reputation_score INTEGER DEFAULT 0,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    is_blacklisted BOOLEAN DEFAULT 0,
                    failed_auth_count INTEGER DEFAULT 0,
                    scan_detected BOOLEAN DEFAULT 0,
                    notes TEXT
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_intel(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_reputation ON threat_intel(reputation_score)')
            
            # System state table (for storing agent state)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            # Config overrides table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            # Audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    target TEXT,
                    details TEXT
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)')
            
            conn.commit()
            logger.info("Database schema initialized")
    
    # ==================== Event Operations ====================
    
    def insert_event(self, event: Event) -> int:
        """Insert event and return ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            d = event.to_dict()
            cursor.execute('''
                INSERT INTO events (timestamp, event_type, source, data, baseline_phase)
                VALUES (?, ?, ?, ?, ?)
            ''', (d['timestamp'], d['event_type'], d['source'], d['data'], d['baseline_phase']))
            return cursor.lastrowid
    
    def get_events(self, limit: int = 100, event_type: Optional[str] = None) -> List[Event]:
        """Get recent events"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if event_type:
                cursor.execute('''
                    SELECT * FROM events WHERE event_type = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (event_type, limit))
            else:
                cursor.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
            
            return [Event.from_dict(dict(row)) for row in cursor.fetchall()]
    
    # ==================== Detection Operations ====================
    
    def insert_detection(self, detection: Detection) -> int:
        """Insert detection and return ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            d = detection.to_dict()
            cursor.execute('''
                INSERT INTO detections 
                (timestamp, detection_type, description, confidence_score, event_ids, data, killchain_stage, baseline_frozen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (d['timestamp'], d['detection_type'], d['description'], d['confidence_score'],
                  d['event_ids'], d['data'], d['killchain_stage'], d['baseline_frozen']))
            return cursor.lastrowid
    
    def get_detections(self, limit: int = 100, min_confidence: float = 0.0) -> List[Detection]:
        """Get recent detections"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM detections 
                WHERE confidence_score >= ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (min_confidence, limit))
            return [Detection.from_dict(dict(row)) for row in cursor.fetchall()]

    def get_detection(self, detection_id: int) -> Optional[Detection]:
        """Get detection by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM detections WHERE id = ?', (detection_id,))
            row = cursor.fetchone()
            return Detection.from_dict(dict(row)) if row else None
    
    # ==================== Action Operations ====================
    
    def insert_action(self, action: Action) -> int:
        """Insert action and return ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            d = action.to_dict()
            cursor.execute('''
                INSERT INTO actions 
                (timestamp, action_type, status, detection_id, target, parameters, snapshot_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (d['timestamp'], d['action_type'], d['status'], d['detection_id'],
                  d['target'], d['parameters'], d['snapshot_id']))
            return cursor.lastrowid
    
    def update_action(self, action_id: int, status: str, result: Optional[str] = None,
                     error: Optional[str] = None, rolled_back: bool = False):
        """Update action status"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE actions 
                SET status = ?, result = ?, error = ?, completed_at = ?, rolled_back = ?
                WHERE id = ?
            ''', (status, result, error, datetime.now(timezone.utc).isoformat(), rolled_back, action_id))
    
    def get_actions(self, limit: int = 100, status: Optional[str] = None) -> List[Action]:
        """Get recent actions"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute('''
                    SELECT * FROM actions WHERE status = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (status, limit))
            else:
                cursor.execute('SELECT * FROM actions ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [Action.from_dict(dict(row)) for row in cursor.fetchall()]

    def get_actions_by_type(self, action_type: str, limit: int = 1000) -> List[Action]:
        """Get recent actions filtered by action_type"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM actions
                WHERE action_type = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (action_type, limit))
            return [Action.from_dict(dict(row)) for row in cursor.fetchall()]
    
    def add_action_feedback(self, action_id: int, feedback: str):
        """Add user feedback to action"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE actions SET user_feedback = ? WHERE id = ?', (feedback, action_id))
    
    # ==================== Baseline Operations ====================
    
    def upsert_baseline(self, baseline: Baseline) -> int:
        """Insert or update baseline"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if exists
            cursor.execute('''
                SELECT id, observation_count, version FROM baselines 
                WHERE baseline_type = ? AND key = ?
            ''', (baseline.baseline_type, baseline.key))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing
                baseline.id = existing['id']
                baseline.observation_count = existing['observation_count'] + 1
                baseline.version = existing['version'] + 1
                
                d = baseline.to_dict()
                cursor.execute('''
                    UPDATE baselines 
                    SET profile = ?, observation_count = ?, last_seen = ?, version = ?, phase = ?
                    WHERE id = ?
                ''', (d['profile'], d['observation_count'], d['last_seen'], d['version'], d['phase'], baseline.id))
                return baseline.id
            else:
                # Insert new
                d = baseline.to_dict()
                cursor.execute('''
                    INSERT INTO baselines 
                    (created_at, baseline_type, phase, key, profile, observation_count, last_seen, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (d['created_at'], d['baseline_type'], d['phase'], d['key'], 
                      d['profile'], d['observation_count'], d['last_seen'], d['version']))
                return cursor.lastrowid
    
    def get_baselines(self, baseline_type: Optional[str] = None) -> List[Baseline]:
        """Get all baselines, optionally filtered by type"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if baseline_type:
                cursor.execute('SELECT * FROM baselines WHERE baseline_type = ?', (baseline_type,))
            else:
                cursor.execute('SELECT * FROM baselines')
            return [Baseline.from_dict(dict(row)) for row in cursor.fetchall()]
    
    def get_baseline(self, baseline_type: str, key: str) -> Optional[Baseline]:
        """Get specific baseline"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM baselines WHERE baseline_type = ? AND key = ?
            ''', (baseline_type, key))
            row = cursor.fetchone()
            return Baseline.from_dict(dict(row)) if row else None
    
    # ==================== Snapshot Operations ====================
    
    def insert_snapshot(self, snapshot: Snapshot) -> int:
        """Insert snapshot and return ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            d = snapshot.to_dict()
            cursor.execute('''
                INSERT INTO snapshots (timestamp, snapshot_type, state_data)
                VALUES (?, ?, ?)
            ''', (d['timestamp'], d['snapshot_type'], d['state_data']))
            return cursor.lastrowid
    
    def get_snapshot(self, snapshot_id: int) -> Optional[Snapshot]:
        """Get snapshot by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM snapshots WHERE id = ?', (snapshot_id,))
            row = cursor.fetchone()
            return Snapshot.from_dict(dict(row)) if row else None
    
    # ==================== Threat Intel Operations ====================
    
    def upsert_threat_intel(self, threat: ThreatIntel) -> int:
        """Insert or update threat intel"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT id FROM threat_intel WHERE ip_address = ?', (threat.ip_address,))
            existing = cursor.fetchone()
            
            d = threat.to_dict()
            
            if existing:
                cursor.execute('''
                    UPDATE threat_intel 
                    SET reputation_score = ?, last_seen = ?, failed_auth_count = ?,
                        scan_detected = ?, notes = ?
                    WHERE ip_address = ?
                ''', (d['reputation_score'], d['last_seen'], d['failed_auth_count'],
                      d['scan_detected'], d['notes'], d['ip_address']))
                return existing['id']
            else:
                cursor.execute('''
                    INSERT INTO threat_intel 
                    (ip_address, reputation_score, first_seen, last_seen, is_blacklisted,
                     failed_auth_count, scan_detected, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (d['ip_address'], d['reputation_score'], d['first_seen'], d['last_seen'],
                      d['is_blacklisted'], d['failed_auth_count'], d['scan_detected'], d['notes']))
                return cursor.lastrowid
    
    def get_threat_intel(self, ip_address: str) -> Optional[ThreatIntel]:
        """Get threat intel for IP"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM threat_intel WHERE ip_address = ?', (ip_address,))
            row = cursor.fetchone()
            return ThreatIntel.from_dict(dict(row)) if row else None
    
    def get_blacklisted_ips(self) -> List[str]:
        """Get all blacklisted IPs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ip_address FROM threat_intel WHERE is_blacklisted = 1')
            return [row['ip_address'] for row in cursor.fetchall()]
    
    # ==================== System State Operations ====================
    
    def set_state(self, key: str, value: str):
        """Set system state value"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO system_state (key, value, updated_at)
                VALUES (?, ?, ?)
            ''', (key, value, datetime.now(timezone.utc).isoformat()))
    
    def get_state(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get system state value"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM system_state WHERE key = ?', (key,))
            row = cursor.fetchone()
            return row['value'] if row else default
    
    # ==================== Audit Log ====================
    
    def add_audit_log(self, event_type: str, actor: str, target: str, details: Dict[str, Any]):
        """Add audit log entry"""
        import json
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO audit_log (timestamp, event_type, actor, target, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now(timezone.utc).isoformat(), event_type, actor, target, json.dumps(details)))
    
    # ==================== Reset Operations ====================
    
    def reset_all(self, keep_audit_log: bool = True) -> Dict[str, int]:
        """
        Reset all data for a clean slate restart.
        
        This clears:
        - All baselines (learned behavior)
        - All detections
        - All actions
        - All events
        - All snapshots
        - System state (phase, freeze status, etc.)
        - Threat intel
        
        Args:
            keep_audit_log: If True, keeps audit log for accountability
            
        Returns:
            Dict with counts of cleared records per table
        """
        cleared = {}
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Get counts before clearing
            tables_to_clear = [
                'baselines',
                'detections', 
                'actions',
                'events',
                'integration_events',
                'snapshots',
                'threat_intel',
                'system_state',
            ]
            
            if not keep_audit_log:
                tables_to_clear.append('audit_log')
            
            for table in tables_to_clear:
                cursor.execute(f'SELECT COUNT(*) as count FROM {table}')
                count = cursor.fetchone()['count']
                cleared[table] = count
                cursor.execute(f'DELETE FROM {table}')
            
            # Log the reset action
            if keep_audit_log:
                cursor.execute('''
                    INSERT INTO audit_log (timestamp, event_type, actor, target, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    datetime.now(timezone.utc).isoformat(),
                    'system_reset',
                    'user',
                    'all_data',
                    json.dumps({'cleared': cleared, 'reason': 'clean_slate_reset'})
                ))
            
            conn.commit()
        
        logger.warning(f"Database reset: {cleared}")
        return cleared
