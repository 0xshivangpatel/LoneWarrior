"""
Baseline Learner - Learns normal system behavior across phases
"""

import logging
from typing import Dict, Any
from datetime import datetime, timezone

from lonewarrior.core.event_bus import EventBus, InternalEvent
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Baseline, BaselinePhase, EventType
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class BaselineLearner:
    """Learns normal system behavior in phases"""
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Subscribe to all events
        self.event_bus.subscribe('*', self.handle_event)
    
    def start(self):
        """Start learner"""
        logger.info("Baseline learner started")
    
    def stop(self):
        """Stop learner"""
        logger.info("Baseline learner stopped")
    
    def handle_event(self, event: InternalEvent):
        """Handle incoming events"""
        # Don't learn if baseline is frozen
        if self.state.is_baseline_frozen():
            return
        
        event_type = event.event_type
        data = event.data
        
        # Learn based on event type
        if event_type == EventType.PROCESS_NEW.value:
            self._learn_process(data)
        elif event_type == EventType.NETWORK_CONNECTION.value:
            self._learn_network(data)
    
    def _learn_process(self, data: Dict[str, Any]):
        """Learn normal process behavior"""
        process_name = data.get('name')
        username = data.get('username')
        
        if not process_name:
            return
        
        key = f"{process_name}:{username}"
        baseline = self.db.get_baseline('process', key)
        
        if baseline:
            baseline.observation_count += 1
            baseline.last_seen = datetime.now(timezone.utc)
        else:
            baseline = Baseline(
                baseline_type='process',
                phase=self.state.get_current_phase().value,
                key=key,
                profile={'name': process_name, 'user': username},
                observation_count=1
            )
            # Record new baseline item for stability tracking
            self.state.record_baseline_change()
        
        self.db.upsert_baseline(baseline)
    
    def _learn_network(self, data: Dict[str, Any]):
        """Learn normal network destinations"""
        remote_addr = data.get('remote_addr')
        remote_port = data.get('remote_port')
        
        if not remote_addr:
            return
        
        key = f"{remote_addr}:{remote_port}"
        baseline = self.db.get_baseline('network_dest', key)
        
        if baseline:
            baseline.observation_count += 1
            baseline.last_seen = datetime.now(timezone.utc)
        else:
            baseline = Baseline(
                baseline_type='network_dest',
                phase=self.state.get_current_phase().value,
                key=key,
                profile={'ip': remote_addr, 'port': remote_port},
                observation_count=1
            )
            # Record new baseline item for stability tracking
            self.state.record_baseline_change()
        
        self.db.upsert_baseline(baseline)
