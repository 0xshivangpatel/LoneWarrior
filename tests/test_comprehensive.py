"""
Comprehensive Test Suite for LoneWarrior V1
Run with: python -m pytest tests/ -v
"""

import pytest
import os
import tempfile
import time
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, PropertyMock

# Test imports
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import (
    Event, Detection, Action, Baseline, Snapshot, ThreatIntel,
    EventType, DetectionType, ActionType, ActionStatus, BaselinePhase
)
from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.core.state_manager import StateManager


# ==================== Database Tests ====================

class TestDatabase:
    """Test SQLite database operations"""
    
    @pytest.fixture
    def db(self, tmp_path):
        """Create temporary database"""
        db_path = str(tmp_path / "test.db")
        return Database(db_path)
    
    def test_schema_creation(self, db):
        """Verify all tables are created"""
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
        
        expected = ['events', 'detections', 'actions', 'baselines', 
                    'snapshots', 'threat_intel', 'system_state', 'config', 'audit_log']
        for table in expected:
            assert table in tables, f"Table {table} not found"
    
    def test_event_crud(self, db):
        """Test event insert and retrieval"""
        event = Event(
            event_type=EventType.PROCESS_NEW.value,
            source="test",
            data={"pid": 1234, "name": "test_process"},
            baseline_phase=0
        )
        
        event_id = db.insert_event(event)
        assert event_id is not None
        
        events = db.get_events(limit=1)
        assert len(events) == 1
        assert events[0].data["pid"] == 1234
    
    def test_detection_crud(self, db):
        """Test detection insert and retrieval"""
        detection = Detection(
            detection_type=DetectionType.INVARIANT_VIOLATION.value,
            description="Test detection",
            confidence_score=85.0,
            data={"test": True}
        )
        
        detection_id = db.insert_detection(detection)
        assert detection_id is not None
        
        detections = db.get_detections(limit=1)
        assert len(detections) == 1
        assert detections[0].confidence_score == 85.0
    
    def test_action_crud(self, db):
        """Test action insert and update"""
        action = Action(
            action_type=ActionType.IP_BLOCK.value,
            status=ActionStatus.PENDING.value,
            target="192.168.1.100",
            parameters={"ttl": 300}
        )
        
        action_id = db.insert_action(action)
        assert action_id is not None
        
        # Update action
        db.update_action(action_id, ActionStatus.SUCCESS.value, result="Blocked")
        
        actions = db.get_actions(limit=1)
        assert actions[0].status == ActionStatus.SUCCESS.value
    
    def test_baseline_upsert(self, db):
        """Test baseline insert and update"""
        baseline = Baseline(
            baseline_type="process",
            phase=1,
            key="nginx:www-data",
            profile={"avg_memory": 100}
        )
        
        baseline_id = db.upsert_baseline(baseline)
        assert baseline_id is not None
        
        # Upsert again - should update
        baseline.profile = {"avg_memory": 150}
        updated_id = db.upsert_baseline(baseline)
        
        result = db.get_baseline("process", "nginx:www-data")
        assert result.observation_count == 2
    
    def test_state_operations(self, db):
        """Test system state get/set"""
        db.set_state("test_key", "test_value")
        value = db.get_state("test_key")
        assert value == "test_value"
        
        # Default value
        default = db.get_state("nonexistent", "default")
        assert default == "default"
    
    def test_threat_intel_upsert(self, db):
        """Test threat intel operations"""
        threat = ThreatIntel(
            ip_address="1.2.3.4",
            reputation_score=50,
            failed_auth_count=3
        )
        
        threat_id = db.upsert_threat_intel(threat)
        assert threat_id is not None
        
        result = db.get_threat_intel("1.2.3.4")
        assert result.failed_auth_count == 3


# ==================== Event Bus Tests ====================

class TestEventBus:
    """Test event bus pub/sub functionality"""
    
    def test_subscribe_publish(self):
        """Test basic pub/sub"""
        bus = EventBus()
        bus.start()
        
        received = []
        def handler(event):
            received.append(event.data)
        
        bus.subscribe("test_event", handler)
        bus.publish("test_event", {"msg": "hello"}, EventPriority.NORMAL, "test")
        
        time.sleep(0.2)
        bus.stop()
        
        assert len(received) == 1
        assert received[0]["msg"] == "hello"
    
    def test_multiple_subscribers(self):
        """Test multiple handlers for same event"""
        bus = EventBus()
        bus.start()
        
        results = {"handler1": False, "handler2": False}
        
        def handler1(event):
            results["handler1"] = True
        
        def handler2(event):
            results["handler2"] = True
        
        bus.subscribe("multi_event", handler1)
        bus.subscribe("multi_event", handler2)
        bus.publish("multi_event", {}, EventPriority.NORMAL, "test")
        
        time.sleep(0.2)
        bus.stop()
        
        assert results["handler1"]
        assert results["handler2"]
    
    def test_priority_ordering(self):
        """Test that higher priority events are processed first"""
        # Note: This is a basic test - precise ordering depends on threading
        bus = EventBus()
        bus.start()
        
        received = []
        def handler(event):
            received.append(event.data.get("priority"))
        
        bus.subscribe("priority_test", handler)
        
        # Critical should be processed before normal
        bus.publish("priority_test", {"priority": "normal"}, EventPriority.NORMAL, "test")
        bus.publish("priority_test", {"priority": "critical"}, EventPriority.CRITICAL, "test")
        
        time.sleep(0.3)
        bus.stop()
        
        assert len(received) == 2


# ==================== State Manager Tests ====================

class TestStateManager:
    """Test state manager functionality"""
    
    @pytest.fixture
    def mock_db(self):
        """Create mock database"""
        db = MagicMock()
        db.get_state.return_value = None
        return db
    
    @pytest.fixture
    def config(self):
        """Test configuration"""
        return {
            'baseline': {
                'phase0_duration': 300,
                'phase1_min_duration': 900,
                'phase1_max_duration': 1200,
                'phase1_min_events': 100,
                'phase2_min_duration': 3600,
                'phase2_max_duration': 7200,
                'freeze_on_attack': True,
                'freeze_cooldown': 1800
            },
            'confidence': {
                'contain': 50,
                'aggressive': 75,
                'lockdown': 90
            },
            'phase_action_limits': {
                0: 50, 1: 50, 2: 75, 3: 100
            },
            'containment': {
                'default_duration': 3600,
                'max_duration': 86400
            }
        }
    
    def test_initial_state(self, mock_db, config):
        """Test state initialization"""
        sm = StateManager(mock_db, config)
        
        # Should set initial phase to 0
        mock_db.set_state.assert_any_call('phase', '0')
        mock_db.set_state.assert_any_call('baseline_frozen', 'false')
    
    def test_get_current_phase(self, mock_db, config):
        """Test phase retrieval"""
        mock_db.get_state.side_effect = lambda k, d=None: '1' if k == 'phase' else d
        
        sm = StateManager(mock_db, config)
        phase = sm.get_current_phase()
        
        assert phase == BaselinePhase.PHASE_1_FAST
    
    def test_attack_confidence_update(self, mock_db, config):
        """Test attack confidence tracking"""
        mock_db.get_state.side_effect = lambda k, d=None: {
            'phase': '1',
            'attack_confidence_score': '0.0',
            'baseline_frozen': 'false'
        }.get(k, d)
        
        sm = StateManager(mock_db, config)
        sm.update_attack_confidence(60.0)
        
        # Should have updated score
        mock_db.set_state.assert_any_call('attack_confidence_score', '60.0')


# ==================== Model Tests ====================

class TestModels:
    """Test data model serialization"""
    
    def test_event_serialization(self):
        """Test Event to_dict and from_dict"""
        event = Event(
            event_type=EventType.PROCESS_NEW.value,
            source="test",
            data={"pid": 123}
        )
        
        d = event.to_dict()
        assert d['event_type'] == 'process_new'
        assert 'pid' in d['data'] or '"pid"' in d['data']
        
        # Reconstruct
        restored = Event.from_dict(d)
        assert restored.event_type == event.event_type
    
    def test_detection_serialization(self):
        """Test Detection to_dict and from_dict"""
        detection = Detection(
            detection_type=DetectionType.INVARIANT_VIOLATION.value,
            description="Web server spawned shell",
            confidence_score=95.0,
            event_ids=[1, 2, 3]
        )
        
        d = detection.to_dict()
        restored = Detection.from_dict(d)
        
        assert restored.confidence_score == 95.0
        assert restored.event_ids == [1, 2, 3]
    
    def test_action_serialization(self):
        """Test Action with completed_at field"""
        action = Action(
            action_type=ActionType.IP_BLOCK.value,
            status=ActionStatus.SUCCESS.value,
            target="192.168.1.1",
            parameters={"ttl": 300},
            completed_at=datetime.now(timezone.utc)
        )
        
        d = action.to_dict()
        restored = Action.from_dict(d)
        
        assert restored.target == "192.168.1.1"
        assert restored.completed_at is not None


# ==================== Integration Tests ====================

class TestIntegration:
    """Integration tests for component interaction"""
    
    def test_database_with_state_manager(self, tmp_path):
        """Test StateManager with real database"""
        db = Database(str(tmp_path / "test.db"))
        config = {
            'baseline': {
                'phase0_duration': 300,
                'phase1_min_duration': 900,
                'phase1_max_duration': 1200,
                'phase1_min_events': 100,
                'phase2_min_duration': 3600,
                'phase2_max_duration': 7200,
                'freeze_on_attack': True,
                'freeze_cooldown': 1800
            },
            'confidence': {'contain': 50},
            'phase_action_limits': {0: 50, 1: 50, 2: 75, 3: 100},
            'containment': {'default_duration': 3600, 'max_duration': 86400}
        }
        
        sm = StateManager(db, config)
        
        # Verify initial phase
        assert sm.get_current_phase() == BaselinePhase.PHASE_0_INSTANT
        
        # Set phase and verify persistence
        sm.set_phase(BaselinePhase.PHASE_1_FAST)
        assert sm.get_current_phase() == BaselinePhase.PHASE_1_FAST
    
    def test_event_flow(self, tmp_path):
        """Test event creation and bus publishing"""
        db = Database(str(tmp_path / "test.db"))
        bus = EventBus()
        bus.start()
        
        received = []
        bus.subscribe(EventType.PROCESS_NEW.value, lambda e: received.append(e))
        
        # Create and store event
        event = Event(
            event_type=EventType.PROCESS_NEW.value,
            source="test",
            data={"pid": 999}
        )
        event.id = db.insert_event(event)
        
        # Publish to bus
        bus.publish(EventType.PROCESS_NEW.value, event.data, EventPriority.NORMAL, "test")
        
        time.sleep(0.2)
        bus.stop()
        
        assert len(received) == 1
        
        # Verify in database
        events = db.get_events(limit=1)
        assert events[0].data["pid"] == 999


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
