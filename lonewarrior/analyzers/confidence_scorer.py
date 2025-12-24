"""
Confidence Scorer - Aggregates signals and triggers actions
"""

import logging
from typing import Dict, Any

from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class ConfidenceScorer:
    """Scores detections and triggers autonomous actions"""
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Subscribe to detection events
        self.event_bus.subscribe('detection_created', self.handle_detection)
    
    def start(self):
        """Start scorer"""
        logger.info("Confidence scorer started")
    
    def stop(self):
        """Stop scorer"""
        logger.info("Confidence scorer stopped")
    
    def handle_detection(self, event: InternalEvent):
        """Handle detection and determine if action is needed"""
        data = event.data
        confidence = data.get('confidence', 0)
        detection_id = data.get('detection_id')
        description = data.get('description')
        
        # Update attack confidence score
        self.state.update_attack_confidence(confidence)
        
        # Determine action based on confidence and phase
        contain_threshold = self.config['confidence']['contain']
        aggressive_threshold = self.config['confidence']['aggressive']
        lockdown_threshold = self.config['confidence']['lockdown']
        
        if confidence >= lockdown_threshold:
            logger.critical(f"LOCKDOWN threshold exceeded: {description}")
            # Trigger containment mode
            if self.config['containment']['auto_enable']:
                self.event_bus.publish(
                    'trigger_containment_mode',
                    {'detection_id': detection_id, 'reason': description},
                    EventPriority.CRITICAL,
                    'ConfidenceScorer'
                )
        
        elif confidence >= aggressive_threshold:
            logger.error(f"AGGRESSIVE threshold exceeded: {description}")
            # Trigger aggressive containment
            self.event_bus.publish(
                'trigger_action',
                {
                    'detection_id': detection_id,
                    'action_level': 'aggressive',
                    'confidence': confidence
                },
                EventPriority.HIGH,
                'ConfidenceScorer'
            )
        
        elif confidence >= contain_threshold:
            logger.warning(f"CONTAIN threshold exceeded: {description}")
            # Trigger basic containment
            self.event_bus.publish(
                'trigger_action',
                {
                    'detection_id': detection_id,
                    'action_level': 'contain',
                    'confidence': confidence
                },
                EventPriority.NORMAL,
                'ConfidenceScorer'
            )
