"""
Simple Component Tests

Tests components in isolation
"""

import pytest
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, Action, DetectionType, ActionType, EventType, ThreatIntel
from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.core.state_manager import StateManager


class TestComponentIsolation:
    """Test components work in isolation"""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory for clean test"""
        data_dir = tmp_path / "test_data"
        data_dir.mkdir(exist_ok=True)
        return data_dir

    def test_auth_collector(self, temp_data_dir):
        """Test auth collector processes auth failures correctly"""
        from lonewarrior.collectors.auth_collector import AuthCollector
        from lonewarrior.core.event_bus import EventBus

        config = {
            'general': {'data_dir': str(temp_data_dir)},
            'baseline': {
                'phase0_duration': 60,
                'freeze_on_attack': True,
            },
            'actions': {
                'enabled': True,
                'ip_block': {
                    'enabled': True,
                    'default_ttl': 10,
                },
                'process_kill': {
                    'enabled': True,
                },
            },
            'threat_intel': {
                'use_builtin_blacklist': True,
                'reputation_tracking': True,
                'external_feeds': {
                    'abuseipdb': {'enabled': True, 'api_key': ''},
                    'project_honeypot': {'enabled': True},
                }
            }

        db = Database(str(temp_data_dir / 'test.db'))
        event_bus = EventBus()
        state_manager = StateManager(db, config)

        collector = AuthCollector(config, db, event_bus, state_manager)
        collector.start()

        # Simulate auth failure
        event_bus.publish(
            EventType.AUTH_FAILURE.value,
            {
                'username': 'testuser',
                'ip': '192.168.1.100',
                'service': 'ssh',
                'port': 22,
                'reason': 'Invalid user',
            },
            source='test',
            timestamp=datetime.now(timezone.utc)
        )

        collector.stop()

    def test_action_executor(self, temp_data_dir):
        """Test action executor blocks IPs"""
        from lonewarrior.responders.action_executor import ActionExecutor
        from lonewarrior.storage.database import Database
        from lonewarrior.core.event_bus import EventBus
        from lonewarrior.config.config_manager import ConfigManager
        from lonewarrior.core.state_manager import StateManager
        from unittest.mock import patch, MagicMock

        config = {
            'general': {'data_dir': str(temp_data_dir)},
            'actions': {
                'enabled': True,
                'ip_block': {
                    'enabled': True,
                    'default_ttl': 10,
                },
            },
        }

        db = Database(str(temp_data_dir / 'test.db')
        event_bus = EventBus()

        with patch('lonewarrior.responders.action_executor.get_privilege_manager') as mock_priv:
            mock_priv = MagicMock()
            mock_priv.can_perform.return_value = True
            mock_priv.can_block.return_value = True
            mock_priv.can_kill.return_value = True

            executor = ActionExecutor(config, db, event_bus, state_manager)
            executor.can_block_ips = True
            executor.can_kill_processes = True
            executor.start()

        # Simulate IP block action
        detection = Detection(
            detection_type=DetectionType.THREAT_INTEL_HIT.value,
            description='Suspicious IP from simulation',
            confidence_score=60.0,
            data={'ip': '192.168.1.100', 'username': 'testsimulator'},
        )
        detection_id = db.insert_detection(detection)

        # Trigger action
        event_bus.publish(
            'trigger_action',
            {
                'detection_id': detection_id,
                'action_level': 'contain',
            },
            source='test'
        )

        # Verify IP block action
        actions = db.get_actions(limit=50)
        ip_blocks = [a for a in actions if a.action_type == ActionType.IP_BLOCK.value]

        assert len(ip_blocks) > 0, "Expected IP block action"

        executor.stop()

    def test_state_manager_phase_transitions(self, temp_data_dir):
        """Test state manager transitions"""
        from lonewarrior.core.state_manager import StateManager
        from lonewarrior.storage.database import Database

        db = Database(str(temp_data_dir / 'test.db')
        config = {
            'phases': {
                'phase0_duration': 10,
                'phase1_duration': 10,
                'phase2_duration': 10,
                'phase3_duration': 10,
            },
        }

        state = StateManager(db, config)

        # Test transitions
        assert state.get_current_phase().value == 0, "Should start in Phase 0"
        state.set_phase(state.PHASE_1_FAST)

        assert state.get_current_phase().value == 1, "Should be in Phase 1"

        # Transition to Phase 2
        state.set_phase(state.PHASE_2_EXPANDED)

        assert state.get_current_phase().value == 2, "Should be in Phase 2"

        # Back to Phase 1
        state.set_phase(state.PHASE_1_FAST)
        assert state.get_current_phase().value == 1, "Should be back in Phase 1"

    def test_threat_intel_analyzer(self, temp_data_dir):
        """Test threat intel analyzer works"""
        from lonewarrior.analyzers.threat_intel_analyzer import ThreatIntelAnalyzer
        from lonewarrior.storage.database import Database
        from lonewarrior.core.event_bus import EventBus

        config = {
            'threat_intel': {
                'use_builtin_blacklist': True,
                'reputation_tracking': True,
                'external_feeds': {
                    'abuseipdb': {'enabled': True, 'api_key': ''},
                    'project_honeypot': {'enabled': True},
                    },
                },
        }

        db = Database(str(temp_data_dir / 'test.db')
        event_bus = EventBus()

        analyzer = ThreatIntelAnalyzer(config, db, event_bus, StateManager)
        analyzer.start()

        # Test reputation update
        threat = ThreatIntel(
            ip_address='192.168.1.100',
            reputation_score=30,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            is_blacklisted=False,
            failed_auth_count=5,
            scan_detected=True,
            notes="Test entry"
        )

        db.upsert_threat_intel(threat)

        # Verify reputation update
        updated_threat = db.get_threat_intel('192.168.1.100')
        assert updated_threat.reputation_score == 30, "Expected reputation score 30"

        analyzer.stop()
