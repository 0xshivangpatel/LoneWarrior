import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, DetectionType, ActionType, ActionStatus
from lonewarrior.core.event_bus import EventBus
from lonewarrior.core.state_manager import StateManager
from lonewarrior.responders.action_executor import ActionExecutor


@pytest.fixture
def mock_privilege_manager():
    """Mock the privilege manager to allow all operations in tests"""
    mock_mgr = MagicMock()
    mock_mgr.can_perform.return_value = True
    mock_mgr.level = MagicMock()
    mock_mgr.capabilities = {'iptables': True, 'kill': True, 'user_mgmt': True}

    def mock_execute(op, params):
        # Return success for all operations
        return True, "OK"

    mock_mgr.execute.side_effect = mock_execute
    return mock_mgr


@pytest.fixture
def config(tmp_path):
    # Minimal config for ActionExecutor
    return {
        "general": {"data_dir": str(tmp_path), "log_dir": str(tmp_path)},
        "actions": {"enabled": True, "ip_block": {"enabled": True, "default_ttl": 10}},
        "health": {"enabled": False, "auto_rollback": True, "critical_services": [], "network_check_host": "8.8.8.8"},
        "baseline": {"freeze_on_attack": True, "freeze_cooldown": 60, "phase0_duration": 300,
                     "phase1_min_duration": 1, "phase1_max_duration": 2, "phase1_min_events": 1,
                     "phase2_min_duration": 1, "phase2_max_duration": 2},
        "confidence": {"contain": 25, "aggressive": 50, "lockdown": 75, "observe": 0},
        "phase_action_limits": {0: 50, 1: 50, 2: 75, 3: 100},
        "containment": {"auto_enable": True, "default_duration": 60, "max_duration": 120},
    }


@pytest.fixture
def db(tmp_path):
    return Database(str(tmp_path / "test.db"))


def test_action_executor_uses_detection_id(db, config, mock_privilege_manager):
    bus = EventBus()
    bus.start()
    sm = StateManager(db, config)

    # Mock the privilege manager to enable IP blocking in tests
    with patch("lonewarrior.responders.action_executor.get_privilege_manager", return_value=mock_privilege_manager):
        ae = ActionExecutor(config, db, bus, sm)
        # Manually enable capabilities for the test
        ae.can_block_ips = True
        ae.can_kill_processes = True
        ae.can_manage_users = True

        det = Detection(
            detection_type=DetectionType.INVARIANT_VIOLATION.value,
            description="Known bad IP",
            confidence_score=90.0,
            data={"ip": "1.2.3.4"},
        )
        det_id = db.insert_detection(det)

        bus.publish("trigger_action", {"detection_id": det_id, "action_level": "contain"}, source="test")
        # dispatch thread is async
        import time
        time.sleep(0.2)

    actions = db.get_actions(limit=10)
    assert any(a.action_type == ActionType.IP_BLOCK.value and a.status == ActionStatus.SUCCESS.value for a in actions)
    bus.stop()


def test_ip_block_ttl_expiry_creates_unblock_action(db, config, mock_privilege_manager):
    bus = EventBus()
    bus.start()
    sm = StateManager(db, config)

    with patch("lonewarrior.responders.action_executor.get_privilege_manager", return_value=mock_privilege_manager):
        ae = ActionExecutor(config, db, bus, sm)
        ae.can_block_ips = True

    # Create a successful IP_BLOCK action already expired
    det = Detection(
        detection_type=DetectionType.BASELINE_DEVIATION.value,
        description="Test",
        confidence_score=30.0,
        data={"ip": "9.9.9.9"},
    )
    det_id = db.insert_detection(det)

        # Insert via ActionExecutor so schema matches expectations
    past = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    from lonewarrior.storage.models import Action
    act_id = db.insert_action(Action(
        action_type=ActionType.IP_BLOCK.value,
        status=ActionStatus.SUCCESS.value,
        detection_id=det_id,
        target="9.9.9.9",
        parameters={"ttl": 1, "expires_at": past},
        snapshot_id=None,
    ))
    assert act_id is not None

    # Simulate: rule exists once, then is gone after delete.
    state = {"present": True}
    def fake_run(cmd, *args, **kwargs):
        class R:
            def __init__(self, rc=0, stdout="", stderr=""):
                self.returncode = rc
                self.stdout = stdout
                self.stderr = stderr
        if cmd[:1] == ["iptables-save"]:
            return R(0, stdout="*filter\nCOMMIT\n")
        if cmd[:2] == ["iptables", "-C"]:
            return R(0 if state["present"] else 1)
        if cmd[:2] == ["iptables", "-D"]:
            state["present"] = False
            return R(0)
        return R(0)

    with patch("lonewarrior.responders.action_executor.subprocess.run", side_effect=fake_run):
        ae._expire_ip_blocks()

    actions = db.get_actions(limit=20)
    assert any(a.action_type == ActionType.IP_UNBLOCK.value for a in actions)
    bus.stop()


def test_containment_enable_applies_rules_and_records_action(db, config, mock_privilege_manager):
    bus = EventBus()
    bus.start()
    sm = StateManager(db, config)

    with patch("lonewarrior.responders.action_executor.get_privilege_manager", return_value=mock_privilege_manager):
        ae = ActionExecutor(config, db, bus, sm)
        ae.can_block_ips = True

    # Trigger containment
    def fake_run(cmd, *args, **kwargs):
        class R:
            def __init__(self, rc=0, stdout="", stderr=""):
                self.returncode = rc
                self.stdout = stdout
                self.stderr = stderr
        if cmd[:1] == ["iptables-save"]:
            return R(0, stdout="*filter\nCOMMIT\n")
        if cmd[:2] == ["iptables", "-C"]:
            return R(1)  # jump doesn't exist
        if cmd[:2] in (["iptables", "-I"], ["iptables", "-N"], ["iptables", "-F"], ["iptables", "-A"]):
            return R(0)
        if cmd[:1] == ["iptables-restore"]:
            return R(0)
        return R(0)

    with patch("lonewarrior.responders.action_executor.subprocess.run", side_effect=fake_run):
        bus.publish("trigger_containment_mode", {"reason": "test"}, source="test")
        import time
        time.sleep(0.2)

    actions = db.get_actions(limit=50)
    assert any(a.action_type == ActionType.CONTAINMENT_MODE_ENABLE.value for a in actions)
    assert db.get_state("containment_snapshot_id") not in (None, "")
    bus.stop()


def test_blacklist_loader_upserts_and_blocks(tmp_path, mock_privilege_manager):
    # Create a fake blacklist file in-place by patching the path resolver
    from lonewarrior.storage.models import ThreatIntel
    cfg = {
        "general": {"data_dir": str(tmp_path), "log_dir": str(tmp_path)},
        "actions": {"enabled": True, "ip_block": {"enabled": True, "default_ttl": 10}},
        "health": {"enabled": False, "auto_rollback": True, "critical_services": [], "network_check_host": "8.8.8.8"},
        "baseline": {"freeze_on_attack": True, "freeze_cooldown": 60, "phase0_duration": 300,
                     "phase1_min_duration": 1, "phase1_max_duration": 2, "phase1_min_events": 1,
                     "phase2_min_duration": 1, "phase2_max_duration": 2},
        "confidence": {"contain": 25, "aggressive": 50, "lockdown": 75, "observe": 0},
        "phase_action_limits": {0: 50, 1: 50, 2: 75, 3: 100},
        "containment": {"auto_enable": True, "default_duration": 60, "max_duration": 120},
        "threat_intel": {"use_builtin_blacklist": True},
    }

    db = Database(str(tmp_path / "test.db"))
    bus = EventBus()
    bus.start()
    sm = StateManager(db, cfg)

    with patch("lonewarrior.responders.action_executor.get_privilege_manager", return_value=mock_privilege_manager):
        ae = ActionExecutor(cfg, db, bus, sm)
        ae.can_block_ips = True

    fake_path = tmp_path / "blacklist_ips.txt"
    fake_path.write_text("# comment\n1.2.3.4\ninvalid\n\n", encoding="utf-8")

    def fake_run(cmd, *args, **kwargs):
        class R:
            def __init__(self, rc=0, stdout="", stderr=""):
                self.returncode = rc
                self.stdout = stdout
                self.stderr = stderr
        if cmd[:1] == ["iptables-save"]:
            return R(0, stdout="*filter\nCOMMIT\n")
        if cmd[:2] == ["iptables", "-C"]:
            return R(1)
        if cmd[:2] in (["iptables", "-I"], ["iptables", "-N"], ["iptables", "-F"], ["iptables", "-A"]):
            return R(0)
        return R(0)

    with patch.object(ae, "_builtin_blacklist_path", return_value=fake_path), \
         patch("lonewarrior.responders.action_executor.subprocess.run", side_effect=fake_run):
        ae._load_and_apply_builtin_blacklist()

    ti = db.get_threat_intel("1.2.3.4")
    assert ti is not None
    assert ti.is_blacklisted is True
    bus.stop()


