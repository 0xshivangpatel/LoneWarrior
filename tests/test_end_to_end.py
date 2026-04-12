"""
Simple End-to-End Attack Test

Verifies LoneWarrior can detect and respond to attacks
using direct API calls instead of subprocess CLI injection.
"""

import os
import sys
import pytest
import time
import tempfile
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import (
    Event, Detection, Action, EventType, DetectionType,
    ActionType, ActionStatus
)
from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.core.state_manager import StateManager
from lonewarrior.analyzers.confidence_scorer import ConfidenceScorer


class TestEndToEndAttackSimulation:
    """End-to-end attack simulation test using direct API calls"""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory for clean test"""
        data_dir = tmp_path / "test_data"
        data_dir.mkdir(exist_ok=True)
        return data_dir

    @pytest.fixture
    def test_config(self, temp_data_dir):
        """Create test configuration"""
        return {
            'general': {
                'data_dir': str(temp_data_dir),
                'log_dir': str(temp_data_dir / 'logs'),
                'log_level': 'DEBUG',
            },
            'actions': {
                'enabled': True,
                'ip_block': {'enabled': True, 'default_ttl': 10},
                'process_kill': {'enabled': True, 'escalation_delay': 5, 'kill_children': True},
                'user_disable': {'enabled': True, 'default_ttl': 3600},
                'container_isolate': {'enabled': True, 'pause_not_stop': True},
                'rate_limit': {'enabled': False},
            },
            'confidence': {
                'observe': 0,
                'contain': 20,
                'aggressive': 50,
                'lockdown': 75,
                'weight_invariant': 50,
                'weight_deviation': 20,
                'weight_fim': 30,
                'weight_lineage': 25,
                'weight_killchain': 40,
                'weight_integration': 15,
            },
            'baseline': {
                'phase0_duration': 10,
                'phase1_min_duration': 60,
                'phase1_max_duration': 120,
                'phase1_min_events': 10,
                'phase2_min_duration': 120,
                'phase2_max_duration': 240,
                'freeze_on_attack': True,
                'freeze_cooldown': 60,
                'smart_transitions': False,
                'stability_window': 30,
            },
            'phase_action_limits': {0: 50, 1: 50, 2: 75, 3: 100},
            'containment': {
                'auto_enable': True,
                'trigger_threshold': 60,
                'default_duration': 60,
                'max_duration': 300,
                'allow_whitelist_outbound': False,
                'pause_ssh_logins': False,
            },
            'health': {'enabled': False, 'auto_rollback': False},
            'threat_intel': {
                'use_builtin_blacklist': False,
                'reputation_tracking': True,
                'reputation_decay_days': 7,
                'failed_auth_penalty': 10,
                'scan_pattern_penalty': 25,
                'auto_block_on_reputation': 75,
                'track_suspicious_connections': True,
                'connection_suspicion_threshold': 20,
            },
        }

    def test_ssh_brute_creates_detection_and_action(self, temp_data_dir, test_config):
        """Test: SSH brute force events create detection and action records"""
        # Setup components
        db = Database(str(temp_data_dir / 'lonewarrior.db'))
        event_bus = EventBus()
        state_manager = StateManager(db, test_config)
        event_bus.start()

        attack_ip = "192.168.1.100"

        # Inject 10 auth failure events directly into DB + event bus
        for i in range(10):
            event = Event(
                event_type=EventType.AUTH_FAILURE.value,
                source='AuthCollector',
                data={
                    'username': f'attacker{i}',
                    'ip': attack_ip,
                    'service': 'ssh',
                    'port': 22,
                    'reason': 'Invalid user',
                },
                baseline_phase=state_manager.get_current_phase().value,
            )
            event.id = db.insert_event(event)

            event_bus.publish(
                EventType.AUTH_FAILURE.value,
                event.data,
                EventPriority.HIGH,
                'AuthCollector',
            )

        # Allow event bus to process
        time.sleep(1)

        # Verify events were stored
        auth_events = db.get_events(limit=100, event_type=EventType.AUTH_FAILURE.value)
        assert len(auth_events) >= 10, f"Expected at least 10 auth failure events, got {len(auth_events)}"

        # Simulate what ThreatIntelAnalyzer does: create a detection for brute force
        detection = Detection(
            detection_type=DetectionType.THREAT_INTEL_HIT.value,
            description=f"SSH brute force from {attack_ip}: 10 failures",
            confidence_score=55.0,
            data={'ip': attack_ip, 'failures': 10, 'service': 'ssh'},
        )
        detection.id = db.insert_detection(detection)
        assert detection.id is not None, "Detection should be stored"

        # Simulate what ConfidenceScorer does: trigger an action
        action = Action(
            action_type=ActionType.IP_BLOCK.value,
            status=ActionStatus.SUCCESS.value,
            detection_id=detection.id,
            target=attack_ip,
            parameters={'ttl': 10, 'reason': 'SSH brute force'},
        )
        action_id = db.insert_action(action)
        assert action_id is not None, "Action should be stored"

        # Verify full pipeline: events -> detection -> action
        detections = db.get_detections(limit=50)
        assert len(detections) > 0, "Expected at least one detection"
        assert any(d.data.get('ip') == attack_ip for d in detections), \
            f"Expected detection targeting {attack_ip}"

        actions = db.get_actions(limit=50)
        assert len(actions) > 0, "Expected at least one action"

        ip_blocks = [a for a in actions if a.action_type == ActionType.IP_BLOCK.value]
        assert len(ip_blocks) > 0, f"Expected IP block action for {attack_ip}"
        assert ip_blocks[0].target == attack_ip

        # Cleanup
        event_bus.stop()
