"""
Action Executor - Executes autonomous actions

Security Design:
- Uses privilege helper for privileged operations when not running as root
- Gracefully degrades when privileges are unavailable
- All inputs are validated before execution
- Audit trail for all actions
"""

import logging
import os
import subprocess
import threading
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lonewarrior.core.event_bus import EventBus, InternalEvent
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Action, ActionType, ActionStatus, Snapshot, ThreatIntel
from lonewarrior.core.state_manager import StateManager
from lonewarrior.utils.validators import validate_ip_address_or_raise
from lonewarrior.core.health_checker import HealthChecker
from lonewarrior.utils.privilege_helper import (
    get_privilege_manager,
    PrivilegedOperation,
    PrivilegeLevel
)


logger = logging.getLogger(__name__)


class ActionExecutor:
    """Executes autonomous containment actions"""

    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        self.health_checker = HealthChecker(config)

        # Privilege manager for secure privilege escalation
        self.priv_mgr = get_privilege_manager(config)

        # Check capabilities
        self.can_block_ips = self.priv_mgr.can_perform(PrivilegedOperation.IPTABLES_BLOCK_IP)
        self.can_kill_processes = self.priv_mgr.can_perform(PrivilegedOperation.KILL_PROCESS)
        self.can_manage_users = self.priv_mgr.can_perform(PrivilegedOperation.DISABLE_USER)

        # Log capability status
        if not self.can_block_ips:
            logger.warning("IP blocking DISABLED - insufficient privileges")
        if not self.can_kill_processes:
            logger.warning("Process killing DISABLED - insufficient privileges")
        if not self.can_manage_users:
            logger.warning("User management DISABLED - insufficient privileges")

        self._running = False
        self._ttl_thread: Optional[threading.Thread] = None

        # Subscribe to action triggers
        self.event_bus.subscribe('trigger_action', self.handle_action_trigger)
        self.event_bus.subscribe('trigger_containment_mode', self.handle_containment_trigger)
    
    def start(self):
        """Start executor"""
        if self._running:
            return
        self._running = True
        self._ttl_thread = threading.Thread(target=self._ttl_loop, daemon=True)
        self._ttl_thread.start()

        # Phase 0: apply builtin blacklist immediately (best-effort)
        try:
            self._load_and_apply_builtin_blacklist()
        except Exception as e:
            logger.error(f"Failed to apply builtin blacklist: {e}", exc_info=True)
        logger.info("Action executor started")
    
    def stop(self):
        """Stop executor"""
        self._running = False
        if self._ttl_thread and self._ttl_thread.is_alive():
            self._ttl_thread.join(timeout=3.0)
        logger.info("Action executor stopped")
    
    def handle_action_trigger(self, event: InternalEvent):
        """Handle action trigger"""
        data = event.data
        detection_id = data.get('detection_id')
        action_level = data.get('action_level')

        logger.info(f"[ACTION_TRIGGER] Received: level={action_level}, detection_id={detection_id}, source={event.source}")

        # Get detection details
        detection = self.db.get_detection(int(detection_id)) if detection_id is not None else None

        if not detection:
            logger.error(f"[ACTION_TRIGGER] Detection {detection_id} not found in database")
            return

        logger.info(f"[ACTION_TRIGGER] Detection found - type: {detection.detection_type}, confidence: {detection.confidence_score}")

        # Determine appropriate action based on detection type and data
        detection_data = detection.data if detection.data else {}

        # Check if this is a process deviation
        if detection_data.get('name') and detection_data.get('username'):
            pid = detection_data.get('pid')
            if pid:
                logger.info(f"[ACTION_TRIGGER] Process deviation detected: {detection_data.get('name')} (PID: {pid}) by {detection_data.get('username')}")
                self.execute_process_kill(int(pid), detection_id, reason="Unknown process deviation")
            else:
                logger.warning(f"[ACTION_TRIGGER] Process detection has no PID - cannot take action: {detection_data}")
        else:
            logger.debug(f"[ACTION_TRIGGER] Not a process deviation - no name/username in data")

        # Check if this is a network deviation or has IP address
        target_ip = detection_data.get('ip') or detection_data.get('remote_addr')
        if target_ip:
            logger.info(f"[ACTION_TRIGGER] Network deviation detected from IP: {target_ip}")
            self.execute_ip_block(target_ip, detection_id)
        else:
            logger.debug(f"[ACTION_TRIGGER] No IP address in detection data")

        # If no specific target, log warning
        if not (detection_data.get('name') or target_ip):
            logger.warning(f"[ACTION_TRIGGER] No actionable target in detection data: {detection_data}")

    def handle_containment_trigger(self, event: InternalEvent):
        """Handle containment mode trigger event"""
        data = event.data
        reason = data.get('reason', 'High confidence attack detected')
        detection_id = data.get('detection_id')

        logger.info(f"[CONTAINMENT_TRIGGER] Received: reason={reason}, detection_id={detection_id}")

        # Trigger containment enforcement
        self._enable_containment_enforcement(reason)

    def execute_process_kill(self, pid: int, detection_id: Optional[int], reason: str = "Suspicious process"):
        """
        Kill a suspicious process.

        Args:
            pid: Process ID to kill
            detection_id: Associated detection ID
            reason: Reason for killing the process
        """
        if not self.can_kill_processes:
            logger.debug(f"Process kill skipped for PID {pid} - insufficient privileges")
            return

        if not self.config['actions']['process_kill']['enabled']:
            logger.info("Process killing disabled in config")
            return

        logger.warning(f"Attempting to kill suspicious process: PID {pid}, reason: {reason}")

        # Create action record
        action = Action(
            action_type=ActionType.PROCESS_KILL.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=detection_id,
            target=f"pid:{pid}",
            parameters={'reason': reason},
        )

        action_id = self.db.insert_action(action)

        try:
            import psutil

            # Check if process exists
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()
            except psutil.NoSuchProcess:
                logger.warning(f"Process {pid} no longer exists")
                self.db.update_action(action_id, ActionStatus.FAILED.value, result="Process no longer exists")
                return

            # Terminate process gracefully first
            proc.terminate()

            # Wait for termination
            import time
            try:
                proc.wait(timeout=5)
                result = f"Terminated process {process_name} (PID: {pid})"
                logger.warning(f"✅ {result}")
                self.db.update_action(action_id, ActionStatus.SUCCESS.value, result=result)
            except psutil.TimeoutExpired:
                # Force kill if graceful termination failed
                logger.warning(f"Process {pid} did not terminate gracefully, forcing kill")
                proc.kill()
                proc.wait(timeout=2)
                result = f"Killed process {process_name} (PID: {pid})"
                logger.warning(f"✅ {result}")
                self.db.update_action(action_id, ActionStatus.SUCCESS.value, result=result)

            # Optional health check
            if self.config['health']['enabled'] and not self.health_checker.check_system_health():
                raise RuntimeError("Health check failed after process kill")

        except ImportError:
            logger.error("psutil not available for process killing")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error="psutil not available")
        except Exception as e:
            logger.error(f"Failed to kill process {pid}: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))

    def execute_ip_block(self, ip_address: str, detection_id: Optional[int]):
        """
        Block an IP address using iptables

        Args:
            ip_address: IP to block
            detection_id: Associated detection ID
        """
        # Check capability first
        if not self.can_block_ips:
            logger.debug(f"IP block skipped for {ip_address} - insufficient privileges")
            return

        # Validate IP address to prevent command injection
        validated_ip = validate_ip_address_or_raise(ip_address)
        if not self.config['actions']['ip_block']['enabled']:
            logger.info("IP blocking disabled in config")
            return

        # Skip localhost IPs - never block localhost
        if self._is_localhost_ip(validated_ip):
            logger.info(f"Skipping localhost IP: {validated_ip} (whitelisted)")
            return
        
        # Create snapshot
        snapshot = self._create_iptables_snapshot()
        snapshot_id = self.db.insert_snapshot(snapshot)
        
        # Create action record
        ttl_seconds = self.config['actions']['ip_block']['default_ttl']
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(ttl_seconds))
        action = Action(
            action_type=ActionType.IP_BLOCK.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=detection_id,
            target=validated_ip,
            parameters={'ttl': int(ttl_seconds), 'expires_at': expires_at.isoformat()},
            snapshot_id=snapshot_id
        )
        
        action_id = self.db.insert_action(action)
        
        try:
            # Execute iptables command
            self._iptables_block_input_ip(validated_ip)
            
            # Optional health check gate + rollback
            if self.config['health']['enabled'] and not self.health_checker.check_system_health():
                raise RuntimeError("Health check failed after IP block")

            self.db.update_action(action_id, ActionStatus.SUCCESS.value, result=f"Blocked {validated_ip} until {expires_at.isoformat()}")
            logger.warning(f"✅ Blocked IP: {validated_ip} (TTL: {ttl_seconds}s)")
        
        except Exception as e:
            logger.error(f"Exception blocking IP: {e}")
            # Rollback to snapshot if enabled
            if self.config['health'].get('auto_rollback', True):
                try:
                    self._rollback_snapshot(snapshot_id)
                    self.db.update_action(action_id, ActionStatus.ROLLED_BACK.value, error=str(e), rolled_back=True)
                    logger.warning("Rolled back iptables rules after failure")
                    return
                except Exception as rb_e:
                    logger.error(f"Rollback failed: {rb_e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
    
    def _create_iptables_snapshot(self) -> Snapshot:
        """Create snapshot of current iptables rules"""
        rules = ""
        try:
            success, result = self.priv_mgr.execute(
                PrivilegedOperation.IPTABLES_SAVE, {}
            )
            if success:
                rules = result
        except Exception as e:
            logger.error(f"Failed to snapshot iptables: {e}")

        return Snapshot(
            snapshot_type='iptables',
            state_data={'rules': rules}
        )

    def _rollback_snapshot(self, snapshot_id: int):
        """Rollback iptables to a stored snapshot"""
        snapshot = self.db.get_snapshot(snapshot_id)
        if not snapshot or snapshot.snapshot_type != 'iptables':
            raise RuntimeError("No iptables snapshot available for rollback")

        rules = snapshot.state_data.get('rules', '')
        if not rules:
            raise RuntimeError("Empty iptables snapshot; refusing rollback")

        success, msg = self.priv_mgr.execute(
            PrivilegedOperation.IPTABLES_RESTORE, {'rules': rules}
        )
        if not success:
            raise RuntimeError(f"Failed to restore iptables: {msg}")

    def _iptables_block_input_ip(self, ip_address: str):
        """Idempotently add an INPUT drop rule for an IP"""
        # Validate IP to prevent command injection
        validated_ip = validate_ip_address_or_raise(ip_address)

        success, msg = self.priv_mgr.execute(
            PrivilegedOperation.IPTABLES_BLOCK_IP, {'ip': validated_ip}
        )
        if not success:
            raise RuntimeError(f"Failed to block IP {validated_ip}: {msg}")

    def _iptables_unblock_input_ip(self, ip_address: str):
        """Idempotently remove an INPUT drop rule for an IP"""
        # Validate IP to prevent command injection
        validated_ip = validate_ip_address_or_raise(ip_address)

        success, msg = self.priv_mgr.execute(
            PrivilegedOperation.IPTABLES_UNBLOCK_IP, {'ip': validated_ip}
        )
        if not success:
            raise RuntimeError(f"Failed to unblock IP {validated_ip}: {msg}")

    def _expire_ip_blocks(self):
        """Remove expired IP blocks"""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)

        # Get all pending IP block actions
        actions = self.db.get_actions(
            action_type=ActionType.IP_BLOCK.value,
            status=ActionStatus.SUCCESS.value
        )

        for action in actions:
            try:
                expires_at = datetime.fromisoformat(
                    action.parameters.get('expires_at', '')
                )
                if now >= expires_at:
                    # Expired - unblock
                    ip_address = action.target
                    self._iptables_unblock_input_ip(ip_address)
                    self.db.update_action(
                        action.id,
                        ActionStatus.EXPIRED.value,
                        result=f"Unblocked {ip_address} (TTL expired)"
                    )
                    logger.info(f"🔄 IP block expired: {ip_address}")
            except Exception as e:
                logger.error(f"Error expiring IP block {action.id}: {e}")

    def _expire_containment_mode(self):
        """Check if containment mode should be disabled"""
        from lonewarrior.storage.models import ActionStatus
        
        # Get all pending containment enable actions
        actions = self.db.get_actions(
            action_type=ActionType.CONTAINMENT_MODE_ENABLE.value,
            status=ActionStatus.SUCCESS.value
        )
        
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        
        for action in actions:
            try:
                expires_at = datetime.fromisoformat(
                    action.parameters.get('expires_at', '')
                )
                if now >= expires_at:
                    # Containment expired - disable it
                    self.event_bus.publish(
                        'disable_containment_mode',
                        {},
                        EventPriority.HIGH,
                        'ActionExecutor'
                    )
                    logger.info(f"Containment mode expired (was active for {action.parameters.get('duration', 0)}s)")
            except Exception as e:
                logger.error(f"Error checking containment expiry: {e}")

    def _enforce_blacklist_blocks(self):
        """Ensure blacklist IPs remain blocked"""
        from lonewarrior.storage.models import ActionStatus, Action
        
        # Get threat intel blacklist
        threats = self.db.get_all_threat_intel()
        
        for threat in threats:
            if threat.is_blacklisted:
                ip = threat.ip_address
                # Check if this IP is already blocked
                existing_actions = self.db.get_actions(
                    action_type=Action.IP_BLOCK.value,
                    limit=100
                )
                
                already_blocked = any(
                    a.target == ip and a.status == ActionStatus.SUCCESS.value
                    for a in existing_actions
                )
                
                if not already_blocked:
                    # Skip localhost IPs
                    if self._is_localhost_ip(ip):
                        continue
                    
                    # Block blacklisted IP with long TTL
                    self.execute_ip_block(ip, None)
                    logger.info(f"Re-enforced blacklist block for {ip}")

    def _is_localhost_ip(self, ip_address: str) -> bool:
        """
        Check if IP is localhost and should never be blocked

        Args:
            ip_address: IP address to check

        Returns:
            True if IP is localhost
        """
        localhost_ips = {
            '127.0.0.1',
            '127.0.0.0',
            '::1',
            'localhost',
        }
        return ip_address in localhost_ips

    def _ttl_loop(self):
        """Background loop to expire time-bound actions (e.g., IP blocks)."""
        while self._running:
            try:
                self._expire_ip_blocks()
                self._expire_containment_mode()
                self._enforce_blacklist_blocks()
            except Exception as e:
                logger.error(f"TTL loop error: {e}", exc_info=True)
            time.sleep(5)

    # ==================== Threat Intel (Phase 0) ====================

    def _builtin_blacklist_path(self) -> Path:
        return Path(__file__).resolve().parent.parent / "threat_intel" / "blacklist_ips.txt"

    def _load_and_apply_builtin_blacklist(self):
        """Load builtin blacklist file into DB and apply temporary blocks immediately."""
        if not self.config.get("threat_intel", {}).get("use_builtin_blacklist", True):
            return

        path = self._builtin_blacklist_path()
        if not path.exists():
            return

        ips = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Basic IPv4 sanity check; skip invalid lines
            parts = line.split(".")
            if len(parts) != 4:
                continue
            try:
                if any(not (0 <= int(p) <= 255) for p in parts):
                    continue
            except Exception:
                continue
            ips.append(line)

        if not ips:
            return

        # Validate all IPs before processing
        validated_ips = []
        for ip in ips:
            try:
                validated_ip = validate_ip_address_or_raise(ip)
                validated_ips.append(validated_ip)
            except ValueError:
                logger.warning(f"Skipping invalid IP in blacklist: {ip}")
                continue
        
        for ip in validated_ips:
            existing = self.db.get_threat_intel(ip)
            if existing:
                existing.is_blacklisted = True
                existing.notes = (existing.notes or "")[:500]
                self.db.upsert_threat_intel(existing)
            else:
                threat = ThreatIntel(ip_address=ip, is_blacklisted=True, notes="builtin_blacklist")
                self.db.upsert_threat_intel(threat)

        # Apply blocks immediately (Phase 0 behavior). We keep them time-bound via TTL loop.
        # We enforce idempotently even if action insert fails (e.g., DB locked).
        for ip in validated_ips:
            try:
                self.execute_ip_block(ip, detection_id=None)
            except Exception:
                try:
                    self._iptables_block_input_ip(ip)
                except Exception:
                    pass

    def _enforce_blacklist_blocks(self):
        """
        Ensure blacklisted IPs remain blocked (time-bound blocks will be re-applied).
        Best-effort; relies on iptables presence.
        """
        if not self.config.get("threat_intel", {}).get("use_builtin_blacklist", True):
            return

        for ip in self.db.get_blacklisted_ips():
            try:
                self._iptables_block_input_ip(ip)
            except Exception:
                continue

    # ==================== Containment Mode Enforcement ====================

    def _enable_containment_enforcement(self, reason: str):
        """
        Apply containment enforcement rules in iptables.

        Safety properties:
        - Takes iptables snapshot first
        - Writes snapshot id into system_state for later rollback
        - Uses a dedicated chain to keep changes isolated
        """
        if not self.state.is_containment_active():
            # Enable containment state first
            self.state.enable_containment_mode()

        snapshot = self._create_iptables_snapshot()
        snapshot_id = self.db.insert_snapshot(snapshot)
        self.db.set_state("containment_snapshot_id", str(snapshot_id))

        action = Action(
            action_type=ActionType.CONTAINMENT_MODE_ENABLE.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=None,
            target="system",
            parameters={"reason": reason, "until": self.db.get_state("containment_until", "")},
            snapshot_id=snapshot_id,
        )
        action_id = self.db.insert_action(action)

        try:
            self._iptables_apply_containment_rules()

            if self.config["health"]["enabled"] and not self.health_checker.check_system_health():
                raise RuntimeError("Health check failed after containment enable")

            self.db.update_action(action_id, ActionStatus.SUCCESS.value, result="Containment enabled")
        except Exception as e:
            logger.error(f"Failed to enable containment enforcement: {e}")
            # Roll back to snapshot
            if self.config["health"].get("auto_rollback", True):
                try:
                    self._rollback_snapshot(snapshot_id)
                    self.db.update_action(action_id, ActionStatus.ROLLED_BACK.value, error=str(e), rolled_back=True)
                    # Ensure state is cleared
                    self.state.disable_containment_mode()
                    self.db.set_state("containment_snapshot_id", "")
                    return
                except Exception as rb_e:
                    logger.error(f"Rollback failed after containment enable failure: {rb_e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))

    def _expire_containment_mode(self):
        """Disable containment enforcement when containment_until has elapsed."""
        if self.state.is_containment_active():
            return

        snapshot_id_str = self.db.get_state("containment_snapshot_id", "")
        if not snapshot_id_str:
            return

        try:
            snapshot_id = int(snapshot_id_str)
        except Exception:
            self.db.set_state("containment_snapshot_id", "")
            return

        action = Action(
            action_type=ActionType.CONTAINMENT_MODE_DISABLE.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=None,
            target="system",
            parameters={"reason": "ttl_expired"},
            snapshot_id=snapshot_id,
        )
        action_id = self.db.insert_action(action)

        try:
            self._rollback_snapshot(snapshot_id)
            if self.config["health"]["enabled"] and not self.health_checker.check_system_health():
                raise RuntimeError("Health check failed after containment disable")
            self.db.update_action(action_id, ActionStatus.SUCCESS.value, result="Containment disabled")
        except Exception as e:
            logger.error(f"Failed to disable containment (rollback snapshot): {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
        finally:
            self.db.set_state("containment_snapshot_id", "")

    def _iptables_apply_containment_rules(self):
        """
        Apply containment rules (iptables).

        V1 behaviors:
        - Outbound default-deny (OUTPUT) except whitelisted IPs/domains (optional)
        - Pause new SSH logins (drop NEW to port 22 on INPUT)
        Notes:
        - Rules are inserted via dedicated chain so rollback is easy via snapshot restore.
        """
        chain = "LW_CONTAIN"

        # Ensure chain exists (iptables -N fails if exists)
        subprocess.run(["iptables", "-N", chain], capture_output=True, text=True, timeout=10)
        # Ensure hooks exist (insert if missing)
        self._iptables_ensure_jump("OUTPUT", chain, position=1)
        self._iptables_ensure_jump("INPUT", chain, position=1)

        # Flush chain to known state
        subprocess.run(["iptables", "-F", chain], capture_output=True, text=True, timeout=10, check=True)

        # Always allow loopback + established/related
        subprocess.run(["iptables", "-A", chain, "-i", "lo", "-j", "ACCEPT"], capture_output=True, text=True, timeout=10)
        subprocess.run(["iptables", "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                       capture_output=True, text=True, timeout=10)

        # Pause NEW SSH logins (inbound) if configured
        if self.config["containment"].get("pause_ssh_logins", True):
            subprocess.run(["iptables", "-A", chain, "-p", "tcp", "--dport", "22",
                            "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"],
                           capture_output=True, text=True, timeout=10)

        # Optional inbound rate limit (best-effort; depends on kernel modules)
        rate_cfg = self.config.get("actions", {}).get("rate_limit", {}) or {}
        if rate_cfg.get("enabled", False):
            limit = int(rate_cfg.get("default_limit", 10))
            # Limit NEW inbound connections per source IP (approx. per minute)
            # If hashlimit module isn't available, iptables will fail; snapshot rollback will recover.
            subprocess.run([
                "iptables", "-A", chain,
                "-m", "conntrack", "--ctstate", "NEW",
                "-m", "hashlimit",
                "--hashlimit-name", "lw_inbound",
                "--hashlimit-mode", "srcip",
                "--hashlimit", f"{limit}/minute",
                "--hashlimit-burst", str(max(5, limit)),
                "-j", "ACCEPT"
            ], capture_output=True, text=True, timeout=10, check=True)

        # Outbound whitelist (optional)
        allow_outbound = self.config["containment"].get("allow_whitelist_outbound", True)
        if allow_outbound:
            for ip in self.config["containment"].get("whitelist_ips", []) or []:
                subprocess.run(["iptables", "-A", chain, "-d", str(ip), "-j", "ACCEPT"],
                               capture_output=True, text=True, timeout=10)

            # Domains (best-effort resolve)
            for domain in self.config["containment"].get("whitelist_domains", []) or []:
                try:
                    import socket
                    resolved = socket.gethostbyname(domain)
                    subprocess.run(["iptables", "-A", chain, "-d", resolved, "-j", "ACCEPT"],
                                   capture_output=True, text=True, timeout=10)
                except Exception:
                    continue

        # Default deny (we apply to OUTPUT by placing jump early; chain ends in DROP)
        subprocess.run(["iptables", "-A", chain, "-j", "DROP"], capture_output=True, text=True, timeout=10, check=True)

    def _iptables_ensure_jump(self, parent_chain: str, child_chain: str, position: int = 1):
        """Ensure parent_chain jumps to child_chain (inserted at a specific position)."""
        check = subprocess.run(["iptables", "-C", parent_chain, "-j", child_chain],
                               capture_output=True, text=True, timeout=10)
        if check.returncode != 0:
            subprocess.run(["iptables", "-I", parent_chain, str(position), "-j", child_chain],
                           capture_output=True, text=True, timeout=10, check=True)

    def _expire_ip_blocks(self):
        """Expire IP blocks whose TTL has elapsed."""
        actions = self.db.get_actions_by_type(ActionType.IP_BLOCK.value, limit=2000)
        now = datetime.now(timezone.utc)
        for a in actions:
            if a.status != ActionStatus.SUCCESS.value:
                continue
            expires_at = (a.parameters or {}).get('expires_at')
            if not expires_at:
                continue
            try:
                exp = datetime.fromisoformat(expires_at)
                # Ensure timezone-aware for comparison
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
            except Exception:
                continue
            if now <= exp:
                continue

            # Create snapshot for unblock (rollback safety)
            snapshot = self._create_iptables_snapshot()
            snapshot_id = self.db.insert_snapshot(snapshot)

            unblock_action = Action(
                action_type=ActionType.IP_UNBLOCK.value,
                status=ActionStatus.EXECUTING.value,
                detection_id=a.detection_id,
                target=a.target,
                parameters={'reason': 'ttl_expired', 'blocked_action_id': a.id},
                snapshot_id=snapshot_id
            )
            unblock_id = self.db.insert_action(unblock_action)

            try:
                self._iptables_unblock_input_ip(a.target)
                if self.config['health']['enabled'] and not self.health_checker.check_system_health():
                    raise RuntimeError("Health check failed after IP unblock")
                self.db.update_action(unblock_id, ActionStatus.SUCCESS.value, result=f"Unblocked {a.target}")
            except Exception as e:
                logger.error(f"Failed to auto-unblock {a.target}: {e}")
                if self.config['health'].get('auto_rollback', True):
                    try:
                        self._rollback_snapshot(snapshot_id)
                        self.db.update_action(unblock_id, ActionStatus.ROLLED_BACK.value, error=str(e), rolled_back=True)
                        continue
                    except Exception as rb_e:
                        logger.error(f"Rollback failed after unblock failure: {rb_e}")
                self.db.update_action(unblock_id, ActionStatus.FAILED.value, error=str(e))
