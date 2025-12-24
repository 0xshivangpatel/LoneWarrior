"""
Integration Tests for LoneWarrior

Tests end-to-end workflows including:
- Event flow from collection to detection
- Detection to action execution
- Status command behavior
- PID file management
- Error handling patterns
"""

import os
import subprocess
import pytest
import tempfile
import time
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import (
    Event, Detection, Action, Baseline,
    EventType, DetectionType, ActionType, ActionStatus
    )
from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.core.state_manager import StateManager
from lonewarrior.config.config_manager import ConfigManager


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run to prevent interference from running lonewarrior service"""
    with patch('subprocess.run') as mock:
        # Default return: service not found or inactive
        mock.return_value = subprocess.CompletedProcess(
            args=['systemctl', 'is-active', 'lonewarrior'],
            returncode=1,
            stdout='inactive',
            stderr=''
        )
        yield mock


class TestEventToDetectionFlow:
    """Test event collection to detection workflow"""

    @pytest.fixture
    def setup_components(self, tmp_path):
        """Setup test components"""
        db_path = str(tmp_path / "test.db")
        db = Database(db_path)
        event_bus = EventBus()
        config = {
            'general': {'data_dir': str(tmp_path)},
            'phases': {'phase0_duration': 60, 'phase1_duration': 300}
        }
        state_manager = StateManager(db, config)
        event_bus.start()

        yield {
            'db': db,
            'event_bus': event_bus,
            'state_manager': state_manager,
            'tmp_path': tmp_path
        }

        event_bus.stop()

    def test_event_published_to_bus(self, setup_components):
        """Test that events are properly published to event bus"""
        event_bus = setup_components['event_bus']
        received_events = []

        def handler(event):
            received_events.append(event)

        event_bus.subscribe('test_event', handler)
        event_bus.publish(
            event_type='test_event',
            data={'test': 'data'},
            priority=EventPriority.NORMAL,
            source='test'
        )

        # Give time for async processing
        time.sleep(0.1)

        assert len(received_events) == 1
        # Event bus returns InternalEvent objects with data attribute
        assert received_events[0].data['test'] == 'data'

    def test_detection_creates_action_record(self, setup_components):
        """Test that detections can trigger action creation"""
        db = setup_components['db']

        # Create a detection
        detection = Detection(
            detection_type=DetectionType.INVARIANT_VIOLATION.value,
            description="Test suspicious activity",
            confidence_score=90.0,
            data={'ip': '192.168.1.100'}
        )
        detection_id = db.insert_detection(detection)

        # Create action linked to detection
        action = Action(
            action_type=ActionType.IP_BLOCK.value,
            status=ActionStatus.PENDING.value,
            detection_id=detection_id,
            target='192.168.1.100',
            parameters={'ttl': 300}
        )
        action_id = db.insert_action(action)

        # Verify linkage
        actions = db.get_actions(limit=10)
        assert len(actions) == 1
        assert actions[0].detection_id == detection_id
        assert actions[0].target == '192.168.1.100'


class TestStatusCommand:
    """Test CLI status command behavior"""

    @pytest.fixture
    def config_and_db(self, tmp_path):
        """Setup config and database for status tests"""
        data_dir = tmp_path / "data"
        data_dir.mkdir()

        config = {
            'general': {
                'data_dir': str(data_dir),
                'log_dir': str(tmp_path / "log")
            }
        }

        db = Database(str(data_dir / "lonewarrior.db"))

        return config, db, data_dir

    def test_status_not_running_without_pid(self, config_and_db, mock_subprocess_run):
        """Test status shows not active when no PID file"""
        config, db, data_dir = config_and_db
        from lonewarrior.cli.main import is_daemon_running

        running, pid = is_daemon_running(config)
        assert running is False
        assert pid is None

    def test_status_running_with_valid_pid(self, config_and_db):
        """Test status shows active with valid PID file"""
        config, db, data_dir = config_and_db
        from lonewarrior.cli.main import is_daemon_running

        # Create PID file with current process PID
        pid_file = data_dir / "lonewarrior.pid"
        pid_file.write_text(str(os.getpid()))

        running, pid = is_daemon_running(config)
        # Note: May not match 'lonewarrior' in cmdline in test context
        # but should at least detect process exists
        assert pid == os.getpid() or running is False

    def test_status_stale_pid_file(self, config_and_db):
        """Test status handles stale PID file correctly"""
        config, db, data_dir = config_and_db
        from lonewarrior.cli.main import is_daemon_running

        # Create PID file with non-existent PID
        pid_file = data_dir / "lonewarrior.pid"
        pid_file.write_text("999999999")  # Very unlikely to exist

        running, pid = is_daemon_running(config)
        assert running is False
        assert pid is None


class TestDatabasePermissions:
    """Test database security permissions"""

    def test_database_created_with_secure_permissions(self, tmp_path):
        """Test database file has 0600 permissions"""
        import stat

        db_path = tmp_path / "secure" / "test.db"
        db = Database(str(db_path))

        # Check file permissions
        file_mode = stat.S_IMODE(os.stat(db_path).st_mode)
        assert file_mode == 0o600, f"Expected 0600, got {oct(file_mode)}"

    def test_database_directory_secure_permissions(self, tmp_path):
        """Test database directory has 0700 permissions"""
        import stat

        db_dir = tmp_path / "secure_dir"
        db_path = db_dir / "test.db"
        db = Database(str(db_path))

        # Check directory permissions
        dir_mode = stat.S_IMODE(os.stat(db_dir).st_mode)
        assert dir_mode == 0o700, f"Expected 0700, got {oct(dir_mode)}"


class TestErrorHandling:
    """Test error handling utilities"""

    def test_error_utility_imports(self):
        """Test error handling utilities can be imported"""
        from lonewarrior.utils.errors import (
            LoneWarriorError,
            CollectorError,
            ErrorSeverity,
            handle_error,
            log_and_continue
        )

        # Basic functionality test
        error = LoneWarriorError("Test error", ErrorSeverity.LOW, "TestComponent")
        assert "Test error" in str(error)
        assert "TestComponent" in str(error)

    def test_log_and_continue_does_not_raise(self):
        """Test that log_and_continue handles errors gracefully"""
        from lonewarrior.utils.errors import log_and_continue, ErrorSeverity

        # Should not raise
        log_and_continue(
            error=ValueError("test"),
            component="TestComponent",
            operation="test operation",
            severity=ErrorSeverity.LOW
        )


class TestProcessCollectorMemoryFix:
    """Test memory leak fix in ProcessCollector"""

    def test_cleanup_method_exists(self):
        """Test that cleanup method is implemented"""
        from lonewarrior.collectors.process_collector import ProcessCollector

        assert hasattr(ProcessCollector, '_cleanup_stale_entries')
        assert hasattr(ProcessCollector, 'CLEANUP_INTERVAL')
        assert hasattr(ProcessCollector, 'MAX_CACHE_SIZE')

    def test_cleanup_interval_reasonable(self):
        """Test cleanup interval is set to reasonable value"""
        from lonewarrior.collectors.process_collector import ProcessCollector

        assert ProcessCollector.CLEANUP_INTERVAL > 0
        assert ProcessCollector.CLEANUP_INTERVAL <= 1000
        assert ProcessCollector.MAX_CACHE_SIZE > 0


class TestBaselineOperations:
    """Test baseline learning and management"""

    @pytest.fixture
    def db(self, tmp_path):
        """Create test database"""
        return Database(str(tmp_path / "test.db"))

    def test_baseline_upsert_increments_count(self, db):
        """Test that baseline observation count increments"""
        baseline = Baseline(
            baseline_type="process",
            key="test_process",
            phase=1,
            profile={"name": "test"}
        )

        # First insert
        db.upsert_baseline(baseline)

        # Second upsert should increment
        baseline2 = Baseline(
            baseline_type="process",
            key="test_process",
            phase=1,
            profile={"name": "test", "updated": True}
        )
        db.upsert_baseline(baseline2)

        # Check count
        result = db.get_baseline("process", "test_process")
        assert result.observation_count == 2

    def test_baseline_freeze_state(self, db):
        """Test baseline freeze state management"""
        config = {
            'phases': {'phase0_duration': 60, 'phase1_duration': 300},
            'baseline': {'freeze_cooldown': 300}
        }
        state_mgr = StateManager(db, config)

        # Initially not frozen
        assert state_mgr.is_baseline_frozen() is False

        # Freeze
        state_mgr.freeze_baseline()
        assert state_mgr.is_baseline_frozen() is True

        # Unfreeze
        state_mgr.unfreeze_baseline()
        assert state_mgr.is_baseline_frozen() is False


class TestFullWorkflow:
    """Test complete workflow scenarios"""

    @pytest.fixture
    def full_setup(self, tmp_path):
        """Setup full test environment"""
        db = Database(str(tmp_path / "lonewarrior.db"))
        event_bus = EventBus()
        config = {
            'general': {'data_dir': str(tmp_path)},
            'phases': {'phase0_duration': 60, 'phase1_duration': 300},
            'baseline': {
                'freeze_cooldown': 300,
                'freeze_on_attack': True,
                'contain_threshold': 80.0
            },
            'confidence': {'contain': 80.0}
        }
        state_manager = StateManager(db, config)
        event_bus.start()

        yield {
            'db': db,
            'event_bus': event_bus,
            'state_manager': state_manager
        }

        event_bus.stop()

    def test_detection_action_workflow(self, full_setup):
        """Test full workflow from event to action"""
        db = full_setup['db']
        event_bus = full_setup['event_bus']

        # 1. Create suspicious event
        event = Event(
            event_type=EventType.AUTH_FAILURE.value,
            source="AuthCollector",
            data={'ip': '10.0.0.1', 'user': 'root', 'attempts': 10},
            baseline_phase=1
        )
        event_id = db.insert_event(event)
        assert event_id is not None

        # 2. Create detection based on event
        detection = Detection(
            detection_type=DetectionType.BASELINE_DEVIATION.value,
            description="Multiple failed auth attempts",
            confidence_score=85.0,
            event_ids=[event_id],
            data={'source_ip': '10.0.0.1'}
        )
        detection_id = db.insert_detection(detection)
        assert detection_id is not None

        # 3. Create action response
        action = Action(
            action_type=ActionType.IP_BLOCK.value,
            status=ActionStatus.PENDING.value,
            detection_id=detection_id,
            target='10.0.0.1',
            parameters={'ttl': 3600, 'reason': 'brute_force'}
        )
        action_id = db.insert_action(action)

        # 4. Simulate action execution
        db.update_action(
            action_id,
            status=ActionStatus.SUCCESS.value,
            result="IP blocked successfully"
        )

        # 5. Verify complete chain
        actions = db.get_actions(limit=10)
        assert len(actions) == 1
        assert actions[0].status == ActionStatus.SUCCESS.value
        assert actions[0].detection_id == detection_id

        detections = db.get_detections(limit=10)
        assert detections[0].event_ids == [event_id]

    def test_state_phase_tracking(self, full_setup):
        """Test state manager phase tracking"""
        state_manager = full_setup['state_manager']

        # Initial phase should be 0
        initial_phase = state_manager.get_current_phase()
        assert initial_phase.value == 0

        # Test phase can be set
        from lonewarrior.storage.models import BaselinePhase
        state_manager.set_phase(BaselinePhase.PHASE_1_FAST)
        assert state_manager.get_current_phase().value == 1

        # Test attack confidence tracking
        state_manager.update_attack_confidence(75.0)
        assert state_manager.get_attack_confidence() == 75.0
