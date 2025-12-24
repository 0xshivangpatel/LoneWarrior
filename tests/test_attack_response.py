"""
End-to-End Attack Response Tests

Tests LoneWarrior's actual response to simulated attacks.
"""

import pytest
import subprocess
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, Action, DetectionType, ActionType, BaselinePhase
from lonewarrior.config.config_manager import ConfigManager
from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority
from lonewarrior.core.state_manager import StateManager


class TestAttackResponse:
    """Test LoneWarrior's detection and response to attacks"""

    @pytest.fixture
    def attack_simulator_path(self):
        """Path to attack simulator script"""
        return Path(__file__).parent.parent / "attack_simulator.py"

    @pytest.fixture
    def mock_subprocess_run(self):
        """Mock subprocess.run to prevent actual system changes"""
        with patch('subprocess.run') as mock:
            mock.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout='', stderr=''
            )
            yield mock

    def test_high_confidence_detection_triggers_action(self, tmp_path, mock_subprocess_run):
        """
        Test: High confidence detection triggers action execution

        Scenario: Detection with confidence 60 (> aggressive threshold of 50)
        Expected: Action executor creates IP block for malicious IP
        """
        # Setup
        db_path = tmp_path / "test.db"
        db = Database(str(db_path))
        event_bus = EventBus()
        event_bus.start()

        config = ConfigManager().load_config()
        state = StateManager(db, config)

        # Mock privilege manager
        with patch('lonewarrior.responders.action_executor.get_privilege_manager') as mock_priv:
            from lonewarrior.responders.action_executor import ActionExecutor

            mock_priv_mgr = MagicMock()
            mock_priv_mgr.can_perform.return_value = True
            mock_priv.return_value = mock_priv_mgr

            action_executor = ActionExecutor(config, db, event_bus, state)
            action_executor.can_block_ips = True
            action_executor.start()

            try:
                # Create high-confidence detection with IP
                detection = Detection(
                    detection_type=DetectionType.BASELINE_DEVIATION.value,
                    description="Unknown process from suspicious IP",
                    confidence_score=60.0,
                    data={'name': 'attacker_tool', 'pid': 9999, 'username': 'root', 'ip': '192.168.1.100'}
                )
                detection_id = db.insert_detection(detection)

                # Trigger action via event bus
                event_bus.publish(
                    'trigger_action',
                    {
                        'detection_id': detection_id,
                        'action_level': 'contain',
                        'confidence': 60.0
                    },
                    source='test'
                )

                # Wait for processing
                time.sleep(0.5)

                # Verify action was created
                actions = db.get_actions(limit=20)
                assert len(actions) > 0, "Expected at least 1 action for high-confidence detection"

                # Should have IP block action
                ip_blocks = [a for a in actions if a.action_type == ActionType.IP_BLOCK.value]
                assert len(ip_blocks) > 0, "Expected IP block action for IP in detection"

                # Verify target IP matches
                assert ip_blocks[0].target == '192.168.1.100', "IP block target should match detection IP"

            finally:
                action_executor.stop()
                event_bus.stop()

    def test_lockdown_threshold_triggers_containment(self, tmp_path, mock_subprocess_run):
        """
        Test: Confidence >= 75 triggers containment mode

        Scenario: Detection with confidence 75 (lockdown threshold)
        Expected: Confidence scorer publishes trigger_containment_mode event
        """
        db_path = tmp_path / "test.db"
        db = Database(str(db_path))
        event_bus = EventBus()
        event_bus.start()

        config_mgr = ConfigManager()
        config = config_mgr.load_config()
        state_mgr = StateManager(db, config)

        from lonewarrior.analyzers.confidence_scorer import ConfidenceScorer
        scorer = ConfidenceScorer(config, db, event_bus, state_mgr)
        scorer.start()

        # Track published events
        published_events = []

        def track_event(event):
            published_events.append((event.event_type, event.data))

        event_bus.subscribe('trigger_containment_mode', track_event)

        try:
            # Create lockdown-level detection
            detection = Detection(
                detection_type=DetectionType.BASELINE_DEVIATION.value,
                description="Critical security violation - suspicious activity",
                confidence_score=75.0,  # Lockdown threshold
                data={'severity': 'critical'}
            )
            detection_id = db.insert_detection(detection)

            # Trigger detection event
            event_bus.publish(
                event_type='detection_created',
                data={
                    'detection_id': detection_id,
                    'type': DetectionType.BASELINE_DEVIATION.value,
                    'description': "Critical security violation",
                    'confidence': 75.0
                },
                source='test'
            )

            # Wait for processing
            time.sleep(0.5)

            # Verify trigger_containment_mode was published
            assert any(e[0] == 'trigger_containment_mode' for e in published_events), \
                "Expected trigger_containment_mode event to be published"

            # Verify baseline was frozen
            assert state_mgr.get_attack_confidence() == 75.0, \
                "Expected attack confidence to be updated"

        finally:
            scorer.stop()
            event_bus.stop()

    def test_detection_event_creates_database_record(self, tmp_path):
        """
        Test: Detection event creates database record with correct fields

        Scenario: Process deviation event published
        Expected: Detection inserted into database with proper confidence
        """
        db_path = tmp_path / "test.db"
        db = Database(str(db_path))
        event_bus = EventBus()
        event_bus.start()

        config_mgr = ConfigManager()
        config = config_mgr.load_config()
        state_mgr = StateManager(db, config)

        from lonewarrior.analyzers.deviation_detector import DeviationDetector
        from lonewarrior.storage.models import BaselinePhase

        detector = DeviationDetector(config, db, event_bus, state_mgr)
        detector.start()

        try:
            # Set state to Phase 1 (after initial learning)
            state_mgr.set_phase(BaselinePhase.PHASE_1_FAST)

            # Publish process event for unknown process
            event_bus.publish(
                event_type='process_new',
                data={
                    'name': 'suspicious_tool',
                    'username': 'attacker',
                    'pid': 1234,
                    'ppid': 1,
                    'parent_name': 'sshd',
                    'cmdline': '/usr/bin/suspicious_tool'
                },
                source='ProcessCollector'
            )

            # Wait for processing
            time.sleep(0.5)

            # Verify detection created
            detections = db.get_detections(limit=20)
            assert len(detections) > 0, "Expected detection from unknown process"

            # Check detection has correct attributes
            det = detections[0]
            assert det.detection_type == DetectionType.BASELINE_DEVIATION.value
            assert det.confidence_score >= 30.0, "Expected confidence >= 30 for unknown process"
            assert 'suspicious_tool' in det.description or 'unknown process' in det.description.lower()

        finally:
            detector.stop()
            event_bus.stop()
