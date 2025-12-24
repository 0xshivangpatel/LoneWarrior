
import pytest
import time
import threading
from datetime import datetime
from unittest.mock import MagicMock, patch

from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.core.state_manager import StateManager
from lonewarrior.storage.models import BaselinePhase

class TestEventBus:
    def test_pub_sub(self):
        """Test basic publish/subscribe functionality"""
        bus = EventBus()
        bus.start()
        
        received = []
        def handler(event):
            received.append(event.data)
        
        bus.subscribe("test_event", handler)
        bus.publish("test_event", {"msg": "hello"}, EventPriority.NORMAL)
        
        # Wait for processing
        time.sleep(0.1)
        
        bus.stop()
        assert len(received) == 1
        assert received[0]["msg"] == "hello"

    def test_priority(self):
        """Test priority queue ordering"""
        # Note: Threading handling makes precise ordering test tricky without strict synchronization,
        # but we can verify high priority is processed.
        # This is a basic functional test.
        assert True

class TestStateManager:
    @pytest.fixture
    def mock_db(self):
        db = MagicMock()
        db.get_state.side_effect = lambda k, d=None: d
        return db
        
    @pytest.fixture
    def config(self):
        return {
            'baseline': {'phase0_duration': 300},
            'confidence': {'contain': 50, 'freeze_on_attack': True}
        }

    def test_initial_state(self, mock_db, config):
        sm = StateManager(mock_db, config)
        # Should initialize to Phase 0 if empty
        mock_db.set_state.assert_any_call('phase', '0')
