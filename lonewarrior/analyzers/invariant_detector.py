"""
Invariant Detector - Detects high-confidence invariant violations
"""

import logging
from typing import Dict, Any

from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, DetectionType, EventType
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


# Processes that should never spawn shells
WEB_PROCESSES = ['nginx', 'apache2', 'httpd', 'php-fpm']
DB_PROCESSES = ['mysql', 'mysqld', 'postgres', 'mongod']

# Shells
SHELLS = ['bash', 'sh', 'zsh', 'fish', 'dash']


class InvariantDetector:
    """Detects invariant violations (high-confidence detections)"""
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Subscribe to process events
        self.event_bus.subscribe(EventType.PROCESS_NEW.value, self.handle_process_event)
    
    def start(self):
        """Start detector"""
        logger.info("Invariant detector started")
    
    def stop(self):
        """Stop detector"""
        logger.info("Invariant detector stopped")
    
    def handle_process_event(self, event: InternalEvent):
        """Handle process events"""
        data = event.data
        process_name = data.get('name', '')
        parent_name = data.get('parent_name', '')
        
        # Web server spawning shell
        if parent_name in WEB_PROCESSES and process_name in SHELLS:
            self._create_detection(
                detection_type=DetectionType.INVARIANT_VIOLATION.value,
                description=f"Web server ({parent_name}) spawned shell ({process_name})",
                confidence_score=95.0,
                data=data
            )
        
        # Database connecting to internet (would need network context)
        # Note: Network correlation is handled by the CorrelationAnalyzer which
        # combines multiple detection types to identify coordinated attacks
    
    def _create_detection(self, detection_type: str, description: str,
                         confidence_score: float, data: Dict[str, Any]):
        """Create and publish detection"""
        detection = Detection(
            detection_type=detection_type,
            description=description,
            confidence_score=confidence_score,
            data=data
        )
        
        detection.id = self.db.insert_detection(detection)
        
        logger.warning(f"🚨 INVARIANT VIOLATION: {description} (confidence: {confidence_score})")
        
        # Publish detection event
        self.event_bus.publish(
            'detection_created',
            {
                'detection_id': detection.id,
                'type': detection_type,
                'description': description,
                'confidence': confidence_score,
            },
            EventPriority.CRITICAL,
            'InvariantDetector'
        )
