"""
Kill-Chain Tracker - Multi-stage attack detection and correlation
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from enum import Enum

from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, DetectionType
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class KillChainStage(Enum):
    """MITRE-inspired kill chain stages"""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class AttackChain:
    """Represents a tracked attack chain"""
    id: str
    started_at: datetime
    last_activity: datetime
    stages: List[KillChainStage] = field(default_factory=list)
    detection_ids: List[int] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    target_processes: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    def add_stage(self, stage: KillChainStage, detection_id: int):
        """Add a stage to the attack chain"""
        if stage not in self.stages:
            self.stages.append(stage)
        self.detection_ids.append(detection_id)
        self.last_activity = datetime.now(timezone.utc)
        self._update_confidence()
    
    def _update_confidence(self):
        """Update confidence based on number of stages"""
        # More stages = higher confidence
        stage_count = len(self.stages)
        if stage_count >= 4:
            self.confidence = 90.0
        elif stage_count >= 3:
            self.confidence = 75.0
        elif stage_count >= 2:
            self.confidence = 50.0
        else:
            self.confidence = 25.0


class KillChainTracker:
    """
    Tracks multi-stage attacks through kill chain progression.
    
    Features:
    - Stage detection from events
    - Attack chain correlation
    - Escalation on multi-stage detection
    - Attack timeline reconstruction
    """
    
    # Event patterns that indicate specific kill chain stages
    STAGE_PATTERNS = {
        KillChainStage.RECONNAISSANCE: [
            'port_scan', 'service_enumeration', 'user_enumeration'
        ],
        KillChainStage.INITIAL_ACCESS: [
            'ssh_brute_force', 'web_exploit', 'phishing_success'
        ],
        KillChainStage.EXECUTION: [
            'shell_spawn', 'script_execution', 'command_execution'
        ],
        KillChainStage.PERSISTENCE: [
            'cron_modified', 'systemd_modified', 'ssh_key_added', 
            'user_created', 'startup_modified'
        ],
        KillChainStage.PRIVILEGE_ESCALATION: [
            'sudo_abuse', 'suid_exploit', 'kernel_exploit', 'root_shell'
        ],
        KillChainStage.CREDENTIAL_ACCESS: [
            'password_dump', 'shadow_access', 'keylog_detected'
        ],
        KillChainStage.DISCOVERY: [
            'system_enumeration', 'network_scan', 'process_list'
        ],
        KillChainStage.LATERAL_MOVEMENT: [
            'ssh_to_internal', 'network_pivot', 'remote_execution'
        ],
        KillChainStage.EXFILTRATION: [
            'large_outbound', 'dns_exfil', 'unusual_destination'
        ],
        KillChainStage.IMPACT: [
            'file_encryption', 'service_disruption', 'data_destruction'
        ]
    }
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Active attack chains
        self.attack_chains: Dict[str, AttackChain] = {}
        
        # Settings
        self.chain_timeout = config.get('detection', {}).get('killchain_timeout', 3600)
        self.escalation_threshold = config.get('detection', {}).get('killchain_escalation_stages', 3)
        
        # Prevent recursive event handling
        self._processing_detection = False
        
        # Subscribe to detection events
        self._event_handlers = [
            ('detection_created', self.handle_detection),
            ('process_new', self.classify_event),
            ('network_connection', self.classify_event),
            ('file_modified', self.classify_event),
            ('auth_failure', self.classify_event),
            ('auth_success', self.classify_event)
        ]
        for event_type, handler in self._event_handlers:
            self.event_bus.subscribe(event_type, handler)
    
    def start(self):
        """Start kill chain tracker"""
        logger.info("Kill-chain tracker started")
    
    def stop(self):
        """Stop kill chain tracker"""
        # Unsubscribe from events
        for event_type, handler in self._event_handlers:
            try:
                self.event_bus.unsubscribe(event_type, handler)
            except Exception as e:
                logger.debug(f"Error unsubscribing from {event_type}: {e}")
        logger.info("Kill-chain tracker stopped")
    
    def handle_detection(self, event: InternalEvent):
        """Handle detection and check for kill chain correlation"""
        # Prevent recursive handling (stage detection triggers detection_created)
        if self._processing_detection:
            return
        
        data = event.data
        detection_id = data.get('detection_id')
        detection_type = data.get('type')
        confidence = data.get('confidence', 0)
        
        # Validate detection_id before use
        if detection_id is None:
            logger.debug("Detection event missing detection_id, skipping")
            return
        
        # Determine kill chain stage
        stage = self._determine_stage_from_detection(detection_type, data)
        
        if stage:
            # Find or create attack chain
            chain_id = self._get_chain_id(data)
            chain = self._get_or_create_chain(chain_id)
            
            # Add stage to chain
            chain.add_stage(stage, detection_id)
            
            # Populate source_ips from data
            ip = data.get('ip') or data.get('remote_addr') or data.get('source_ip')
            if ip and ip not in chain.source_ips:
                chain.source_ips.append(ip)
            
            # Populate target_processes from data
            process_name = data.get('process_name') or data.get('name')
            if process_name and process_name not in chain.target_processes:
                chain.target_processes.append(process_name)
            
            logger.warning(f"Kill-chain stage detected: {stage.value} (chain: {chain_id})")
            
            # Check for escalation
            if len(chain.stages) >= self.escalation_threshold:
                self._escalate_chain(chain)
    
    def classify_event(self, event: InternalEvent):
        """Classify raw event into kill chain stage"""
        data = event.data
        event_type = event.event_type
        
        stage = None
        indicators = []
        
        # Check for shell spawning from web server
        if event_type == 'process_new':
            parent_name = data.get('parent_name', '')
            process_name = data.get('name', '')
            
            if parent_name in ['nginx', 'apache2', 'httpd', 'php-fpm']:
                if process_name in ['bash', 'sh', 'dash', 'zsh']:
                    stage = KillChainStage.EXECUTION
                    indicators.append('web_server_shell_spawn')
        
        # Check for persistence mechanisms
        if event_type == 'file_modified':
            filepath = data.get('filepath', '')
            
            if '/cron' in filepath:
                stage = KillChainStage.PERSISTENCE
                indicators.append('cron_modified')
            elif '/.ssh/authorized_keys' in filepath:
                stage = KillChainStage.PERSISTENCE
                indicators.append('ssh_key_added')
            elif '/systemd/' in filepath:
                stage = KillChainStage.PERSISTENCE
                indicators.append('systemd_modified')
        
        # Check for brute force
        if event_type == 'auth_failure':
            ip = data.get('ip')
            if ip:
                # Count recent failures from this IP
                count = self._count_recent_failures(ip)
                if count >= 5:
                    stage = KillChainStage.INITIAL_ACCESS
                    indicators.append('ssh_brute_force')
        
        # Check for unusual outbound connections
        if event_type == 'network_connection':
            remote_port = data.get('remote_port', 0)
            bytes_sent = data.get('bytes_sent', 0)
            
            # Large outbound transfer to unusual port
            if bytes_sent > 1024 * 1024 and remote_port not in [80, 443, 22, 53]:
                stage = KillChainStage.EXFILTRATION
                indicators.append('large_outbound')
        
        if stage and indicators:
            self._create_stage_detection(stage, indicators, data)
    
    def _determine_stage_from_detection(self, detection_type: str, 
                                        data: Dict[str, Any]) -> Optional[KillChainStage]:
        """Determine kill chain stage from detection type"""
        stage_mapping = {
            DetectionType.INVARIANT_VIOLATION.value: KillChainStage.EXECUTION,
            DetectionType.BASELINE_DEVIATION.value: KillChainStage.DISCOVERY,
            DetectionType.FIM_HIT.value: KillChainStage.PERSISTENCE,
            DetectionType.NETWORK_ANOMALY.value: KillChainStage.EXFILTRATION,
        }
        
        return stage_mapping.get(detection_type)
    
    def _get_chain_id(self, data: Dict[str, Any]) -> str:
        """Generate chain ID for correlation"""
        # Use source IP + time window for correlation
        ip = data.get('ip') or data.get('remote_addr') or 'unknown'
        
        # Check existing chains for this IP
        for chain_id, chain in self.attack_chains.items():
            if ip in chain.source_ips:
                age = (datetime.now(timezone.utc) - chain.last_activity).total_seconds()
                if age < self.chain_timeout:
                    return chain_id
        
        # New chain
        return f"chain_{ip}_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    
    def _get_or_create_chain(self, chain_id: str) -> AttackChain:
        """Get existing chain or create new one"""
        if chain_id not in self.attack_chains:
            self.attack_chains[chain_id] = AttackChain(
                id=chain_id,
                started_at=datetime.now(timezone.utc),
                last_activity=datetime.now(timezone.utc)
            )
        
        return self.attack_chains[chain_id]
    
    def _escalate_chain(self, chain: AttackChain):
        """Escalate when multi-stage attack detected"""
        stages_str = ' → '.join([s.value for s in chain.stages])
        
        logger.critical(f"🚨 MULTI-STAGE ATTACK DETECTED: {stages_str}")
        logger.critical(f"   Chain ID: {chain.id}")
        logger.critical(f"   Confidence: {chain.confidence}%")
        
        # Create kill-chain detection
        detection = Detection(
            detection_type=DetectionType.KILLCHAIN_STAGE.value,
            description=f"Multi-stage attack: {stages_str}",
            confidence_score=chain.confidence,
            event_ids=chain.detection_ids,
            killchain_stage=chain.stages[-1].value,
            data={
                'chain_id': chain.id,
                'stages': [s.value for s in chain.stages],
                'source_ips': chain.source_ips
            }
        )
        
        detection.id = self.db.insert_detection(detection)
        
        # Publish high-priority detection
        self.event_bus.publish(
            'detection_created',
            {
                'detection_id': detection.id,
                'type': DetectionType.KILLCHAIN_STAGE.value,
                'description': detection.description,
                'confidence': chain.confidence,
                'killchain_stages': [s.value for s in chain.stages]
            },
            EventPriority.CRITICAL,
            'KillChainTracker'
        )
    
    def _create_stage_detection(self, stage: KillChainStage, 
                               indicators: List[str], data: Dict[str, Any]):
        """Create detection for identified kill chain stage"""
        # Set flag to prevent recursive handling
        self._processing_detection = True
        
        try:
            detection = Detection(
                detection_type=DetectionType.KILLCHAIN_STAGE.value,
                description=f"Kill-chain stage: {stage.value} ({', '.join(indicators)})",
                confidence_score=40.0,
                killchain_stage=stage.value,
                data={'indicators': indicators, **data}
            )
            
            detection.id = self.db.insert_detection(detection)
            
            self.event_bus.publish(
                'detection_created',
                {
                    'detection_id': detection.id,
                    'type': DetectionType.KILLCHAIN_STAGE.value,
                    'description': detection.description,
                    'confidence': 40.0
                },
                EventPriority.HIGH,
                'KillChainTracker'
            )
        finally:
            self._processing_detection = False
    
    def _count_recent_failures(self, ip: str, window_seconds: int = 300) -> int:
        """
        Count recent auth failures from an IP.
        
        Note: This queries auth_failure events (raw data), NOT brute_force detections
        to avoid circular logic where we'd be counting our own previous alerts.
        """
        try:
            # Query recent auth failure events from database (raw events, not detections)
            from datetime import timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
            
            # Get recent auth failure events - these are raw login failures
            # NOT brute_force detections (which would be circular)
            recent_events = self.db.get_recent_events(
                event_type='auth_failure',
                since=cutoff,
                limit=500
            )
            
            # Count failures from this specific IP
            count = 0
            for event in recent_events:
                event_data = event.data if hasattr(event, 'data') else {}
                event_ip = event_data.get('ip') or event_data.get('source_ip')
                if event_ip == ip:
                    count += 1
            
            return count
        except AttributeError:
            # Fallback: db.get_recent_events may not exist, try alternative
            try:
                # Try to count from state manager's recent events cache
                recent_failures = self.state.get_recent_auth_failures(ip, window_seconds)
                return len(recent_failures) if recent_failures else 0
            except Exception:
                return 0
        except Exception as e:
            logger.debug(f"Error counting auth failures for {ip}: {e}")
            return 0
    
    def get_active_chains(self) -> List[Dict[str, Any]]:
        """Get all active attack chains for reporting"""
        result = []
        now = datetime.now(timezone.utc)
        
        for chain_id, chain in self.attack_chains.items():
            age = (now - chain.last_activity).total_seconds()
            if age < self.chain_timeout:
                result.append({
                    'id': chain.id,
                    'started': chain.started_at.isoformat(),
                    'last_activity': chain.last_activity.isoformat(),
                    'stages': [s.value for s in chain.stages],
                    'confidence': chain.confidence,
                    'source_ips': chain.source_ips
                })
        
        return result
    
    def cleanup_old_chains(self):
        """Remove expired attack chains"""
        now = datetime.now(timezone.utc)
        expired = []
        
        for chain_id, chain in self.attack_chains.items():
            age = (now - chain.last_activity).total_seconds()
            if age > self.chain_timeout:
                expired.append(chain_id)
        
        for chain_id in expired:
            del self.attack_chains[chain_id]
        
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired attack chains")
