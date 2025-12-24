"""
Correlation Analyzer - Correlates multiple low-confidence detections to identify coordinated attacks
"""

import logging
from typing import Dict, Any, List
from datetime import datetime, timedelta, timezone

from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class CorrelationAnalyzer:
    """Correlates multiple detections to identify multi-vector attacks"""

    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager

        # Track recent detections for correlation
        self.recent_detections: List[Dict[str, Any]] = []
        self.correlation_window = 300  # 5 minutes correlation window

        # Subscribe to detection events
        self.event_bus.subscribe('detection_created', self.handle_detection)

    def start(self):
        """Start correlation analyzer"""
        logger.info("Correlation analyzer started")

    def stop(self):
        """Stop correlation analyzer"""
        logger.info("Correlation analyzer stopped")

    def handle_detection(self, event: InternalEvent):
        """Handle detection and correlate with others"""
        data = event.data
        detection_id = data.get('detection_id')
        confidence = data.get('confidence', 0)
        detection_type = data.get('type', '')

        # Prevent feedback loop: skip correlated_threat detections
        if detection_type == 'correlated_threat':
            return

        # Get full detection details
        detection = self.db.get_detection(int(detection_id)) if detection_id else None
        if not detection:
            return

        # Add to recent detections
        self.recent_detections.append({
            'id': detection_id,
            'timestamp': datetime.now(timezone.utc),
            'confidence': confidence,
            'type': detection_type,
            'data': detection.data or {}
        })

        # Cleanup old detections outside correlation window
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.correlation_window)
        self.recent_detections = [
            d for d in self.recent_detections
            if d['timestamp'] > cutoff
        ]

        # Run correlation analysis
        correlated_threats = self._analyze_correlations()

        # If high-confidence correlated threat found, publish event
        if correlated_threats:
            self._publish_correlated_threat(correlated_threats)

    def _analyze_correlations(self) -> Dict[str, Any]:
        """
        Analyze recent detections for correlated patterns.

        Returns:
            Dict with correlated threat information
        """
        if len(self.recent_detections) < 2:
            return {}

        # Group detections by type and time
        type_counts: Dict[str, int] = {}
        for det in self.recent_detections:
            det_type = det['type']
            type_counts[det_type] = type_counts.get(det_type, 0) + 1

        # Check for multiple detection types (multi-vector attack)
        unique_types = set(type_counts.keys())
        if len(unique_types) >= 2:
            # Multiple detection types suggest coordinated attack
            total_confidence = sum(d['confidence'] for d in self.recent_detections)
            avg_confidence = total_confidence / len(self.recent_detections)

            return {
                'threat_type': 'multi_vector_attack',
                'unique_detection_types': len(unique_types),
                'total_detections': len(self.recent_detections),
                'avg_confidence': avg_confidence,
                'detection_types': list(unique_types),
                'confidence_boost': min(len(unique_types) * 15, 50)  # Boost confidence
            }

        # Check for rapid low-confidence detections
        low_confidence_count = sum(
            1 for d in self.recent_detections
            if d['confidence'] < 40
        )

        if low_confidence_count >= 3:
            # Multiple low-confidence detections in short time
            return {
                'threat_type': 'rapid_low_confidence',
                'low_confidence_count': low_confidence_count,
                'time_window': self.correlation_window,
                'confidence_boost': low_confidence_count * 10
            }

        return {}

    def _publish_correlated_threat(self, threat_info: Dict[str, Any]):
        """Publish correlated threat event"""
        logger.warning(
            f"[CORRELATION] {threat_info['threat_type']}: "
            f"{threat_info}"
        )

        # Create enhanced detection
        from lonewarrior.storage.models import Detection, DetectionType

        description = f"Correlated threat detected: {threat_info['threat_type']}"
        confidence_boost = threat_info.get('confidence_boost', 20)

        enhanced_detection = Detection(
            detection_type=DetectionType.CORRELATED_THREAT.value,
            description=description,
            confidence_score=confidence_boost,
            data=threat_info
        )

        detection_id = self.db.insert_detection(enhanced_detection)

        # Publish correlated threat event
        self.event_bus.publish(
            'detection_created',
            {
                'detection_id': detection_id,
                'type': DetectionType.CORRELATED_THREAT.value,
                'description': description,
                'confidence': confidence_boost,
            },
            EventPriority.HIGH,
            'CorrelationAnalyzer'
        )
