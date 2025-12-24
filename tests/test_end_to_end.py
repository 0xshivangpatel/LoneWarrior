"""
Simple End-to-End Attack Test

Verifies LoneWarrior can detect and respond to attacks
"""

import os
import sys
import pytest
import subprocess
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, Action, DetectionType, ActionType


class TestEndToEndAttackSimulation:
    """End-to-end attack simulation test"""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory for clean test"""
        data_dir = tmp_path / "test_data"
        data_dir.mkdir(exist_ok=True)
        return data_dir

    def test_ssh_brute_creates_detection_and_action(self, temp_data_dir):
        """Test: SSH brute force creates detection and IP block action"""
        print("\n[TEST] Starting LoneWarrior...")
        
        # Config
        test_config = {
            'general': {'data_dir': str(temp_data_dir), 'log_dir': str(temp_data_dir / 'logs')},
            'actions': {'enabled': True, 'ip_block': {'enabled': True, 'default_ttl': 10}},
            'confidence': {'contain': 20},  # Low threshold
            'phases': {
                'phase0_duration': 10,  # Skip Phase 0 to allow detection
                'phase1_duration': 60,
            }
        }
        
        config_file = temp_data_dir / 'test_config.yaml'
        import yaml
        with open(config_file, 'w') as f:
            yaml.dump(test_config, f)
        
        # Start LoneWarrior
        lw_proc = subprocess.Popen(
            [sys.executable, '-m', 'lonewarrior', '--config', str(config_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(3)  # Wait for LW to start
        
        # Inject 10 auth failure events from same IP
        attack_ip = "192.168.1.100"
        print(f"[TEST] Injecting auth failures from {attack_ip}...")
        
        for i in range(10):
            cmd = [
                sys.executable,
                '-m', 'lonewarrior',
                'event', 'create',
                'auth_failure',
                '--username', f'attacker{i}',
                '--ip', attack_ip,
                '--service', 'ssh',
                '--port', '22',
                '--reason', 'Invalid user'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                print(f"[TEST] Failed to inject event #{i+1}: {result.stderr}")
            else:
                print(f"[TEST] Injected auth failure #{i+1}")
        
        time.sleep(5)  # Wait for processing
        
        # Check database
        db = Database(str(temp_data_dir / 'lonewarrior.db'))
        
        # Check detections
        detections = db.get_detections(limit=50)
        print(f"[TEST] Found {len(detections)} detections")
        assert len(detections) > 0, f"Expected detection from auth failures"
        
        # Check auth failure events
        auth_events = db.get_events(limit=100, event_type='auth_failure')
        print(f"[TEST] Found {len(auth_events)} auth failure events")
        assert len(auth_events) >= 10, f"Expected at least 10 auth failure events"
        
        # Check for actions
        actions = db.get_actions(limit=50)
        print(f"[TEST] Found {len(actions)} actions")
        
        # Verify IP block action was taken
        ip_blocks = [a for a in actions if a.action_type == ActionType.IP_BLOCK.value]
        assert len(ip_blocks) > 0, f"Expected IP block action for {attack_ip}"
        
        # Log action details
        for action in actions[:5]:
            print(f"[TEST] Action: {action.action_type} - Target: {action.target} - Status: {action.status}")
        
        # Cleanup
        print("\n[TEST] Cleanup...")
        lw_proc.terminate()
        try:
            lw_proc.wait(timeout=5)
        except:
            pass
        
        print("[TEST] Complete - All assertions passed!")
