"""
Data models for LoneWarrior database entities
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
import json


class BaselinePhase(Enum):
    """Baseline learning phases"""
    PHASE_0_INSTANT = 0    # 0-5 minutes: Instant safety
    PHASE_1_FAST = 1       # 15-20 minutes: Fast baseline
    PHASE_2_EXPANDED = 2    # 1-2 hours: Expanded baseline
    PHASE_3_CONTINUOUS = 3  # Forever: Continuous learning


class EventType(Enum):
    """Types of security events"""
    PROCESS_NEW = "process_new"
    PROCESS_TERMINATED = "process_terminated"
    NETWORK_CONNECTION = "network_connection"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    FILE_MODIFIED = "file_modified"
    FILE_CREATED = "file_created"
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    CONTAINER_STARTED = "container_started"
    USER_CREATED = "user_created"


class DetectionType(Enum):
    """Types of detections"""
    INVARIANT_VIOLATION = "invariant_violation"
    BASELINE_DEVIATION = "baseline_deviation"
    FIM_HIT = "fim_hit"
    LINEAGE_VIOLATION = "lineage_violation"
    NETWORK_ANOMALY = "network_anomaly"
    KILLCHAIN_STAGE = "killchain_stage"
    INTEGRATION_SIGNAL = "integration_signal"
    THREAT_INTEL_HIT = "threat_intel_hit"
    CORRELATED_THREAT = "correlated_threat"


class ActionType(Enum):
    """Types of autonomous actions"""
    IP_BLOCK = "ip_block"
    IP_UNBLOCK = "ip_unblock"
    PROCESS_KILL = "process_kill"
    USER_DISABLE = "user_disable"
    USER_ENABLE = "user_enable"
    CONTAINER_ISOLATE = "container_isolate"
    CONTAINER_RESTORE = "container_restore"
    RATE_LIMIT = "rate_limit"
    CONTAINMENT_MODE_ENABLE = "containment_mode_enable"
    CONTAINMENT_MODE_DISABLE = "containment_mode_disable"


class ActionStatus(Enum):
    """Status of an action"""
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class Event:
    """Security event collected from the system"""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str = ""
    source: str = ""  # collector name
    data: Dict[str, Any] = field(default_factory=dict)
    baseline_phase: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        d['data'] = json.dumps(self.data)
        return d
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Event':
        """Create from dictionary"""
        if isinstance(d['timestamp'], str):
            d['timestamp'] = datetime.fromisoformat(d['timestamp'])
        if isinstance(d['data'], str):
            d['data'] = json.loads(d['data'])
        return cls(**d)


@dataclass
class Detection:
    """Security threat detection"""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    detection_type: str = ""
    description: str = ""
    confidence_score: float = 0.0
    event_ids: List[int] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    killchain_stage: Optional[str] = None
    baseline_frozen: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        d['event_ids'] = json.dumps(self.event_ids)
        d['data'] = json.dumps(self.data)
        return d
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Detection':
        """Create from dictionary"""
        if isinstance(d['timestamp'], str):
            d['timestamp'] = datetime.fromisoformat(d['timestamp'])
        if isinstance(d['event_ids'], str):
            d['event_ids'] = json.loads(d['event_ids'])
        if isinstance(d['data'], str):
            d['data'] = json.loads(d['data'])
        return cls(**d)


@dataclass
class Action:
    """Autonomous action taken by the system"""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action_type: str = ""
    status: str = ActionStatus.PENDING.value
    detection_id: Optional[int] = None
    target: str = ""  # IP, PID, username, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    snapshot_id: Optional[int] = None
    result: Optional[str] = None
    error: Optional[str] = None
    completed_at: Optional[datetime] = None
    rolled_back: bool = False
    user_feedback: Optional[str] = None  # 'correct', 'false_positive', 'too_aggressive'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        d['parameters'] = json.dumps(self.parameters)
        if d['completed_at']:
            d['completed_at'] = d['completed_at'].isoformat() if isinstance(d['completed_at'], datetime) else d['completed_at']
        return d
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Action':
        """Create from dictionary"""
        if isinstance(d['timestamp'], str):
            d['timestamp'] = datetime.fromisoformat(d['timestamp'])
        if d.get('completed_at') and isinstance(d['completed_at'], str):
            d['completed_at'] = datetime.fromisoformat(d['completed_at'])
        if isinstance(d['parameters'], str):
            d['parameters'] = json.loads(d['parameters'])
        return cls(**d)


@dataclass
class Baseline:
    """Baseline profile for normal behavior"""
    id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    baseline_type: str = ""  # 'process', 'network', 'rate', 'auth'
    phase: int = 0
    key: str = ""  # identifier (process name, destination IP, etc.)
    profile: Dict[str, Any] = field(default_factory=dict)
    observation_count: int = 1
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['created_at'] = self.created_at.isoformat()
        d['last_seen'] = self.last_seen.isoformat()
        d['profile'] = json.dumps(self.profile)
        return d
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Baseline':
        """Create from dictionary"""
        if isinstance(d['created_at'], str):
            d['created_at'] = datetime.fromisoformat(d['created_at'])
        if isinstance(d['last_seen'], str):
            d['last_seen'] = datetime.fromisoformat(d['last_seen'])
        if isinstance(d['profile'], str):
            d['profile'] = json.loads(d['profile'])
        return cls(**d)


@dataclass
class Snapshot:
    """System state snapshot before action"""
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    snapshot_type: str = ""  # 'iptables', 'user_state', 'container_state'
    state_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        d['state_data'] = json.dumps(self.state_data)
        return d
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Snapshot':
        """Create from dictionary"""
        if isinstance(d['timestamp'], str):
            d['timestamp'] = datetime.fromisoformat(d['timestamp'])
        if isinstance(d['state_data'], str):
            d['state_data'] = json.loads(d['state_data'])
        return cls(**d)


@dataclass
class ThreatIntel:
    """Threat intelligence entry"""
    id: Optional[int] = None
    ip_address: str = ""
    reputation_score: int = 0  # 0-100, higher = more malicious
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_blacklisted: bool = False
    failed_auth_count: int = 0
    scan_detected: bool = False
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        d = asdict(self)
        d['first_seen'] = self.first_seen.isoformat()
        d['last_seen'] = self.last_seen.isoformat()
        return d
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'ThreatIntel':
        """Create from dictionary"""
        if isinstance(d['first_seen'], str):
            d['first_seen'] = datetime.fromisoformat(d['first_seen'])
        if isinstance(d['last_seen'], str):
            d['last_seen'] = datetime.fromisoformat(d['last_seen'])
        # SQLite stores booleans as integers 0/1
        if 'is_blacklisted' in d:
            d['is_blacklisted'] = bool(d['is_blacklisted'])
        if 'scan_detected' in d:
            d['scan_detected'] = bool(d['scan_detected'])
        return cls(**d)
