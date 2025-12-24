"""
Privilege Helper - Secure privilege escalation for LoneWarrior

This module provides a secure way to execute privileged operations without
running the entire application as root. It uses a helper script that can be
invoked via sudo with strict input validation.

Security Design:
1. Main daemon runs as unprivileged user 'lonewarrior'
2. Privileged operations are delegated to lw-privilege-helper
3. Helper validates ALL inputs before execution
4. Helper only allows a whitelist of specific operations
5. All privileged operations are audit logged
6. Sudo rules restrict helper to specific commands only
"""

import os
import json
import logging
import subprocess
import shutil
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
from enum import Enum

from lonewarrior.utils.validators import validate_ip_address_or_raise


logger = logging.getLogger(__name__)


class PrivilegeLevel(Enum):
    """Available privilege levels"""
    NONE = "none"           # No privileges needed
    HELPER = "helper"       # Use privilege helper (sudo)
    ROOT = "root"           # Full root (legacy mode)


class PrivilegedOperation(Enum):
    """Whitelisted privileged operations"""
    IPTABLES_BLOCK_IP = "iptables_block_ip"
    IPTABLES_UNBLOCK_IP = "iptables_unblock_ip"
    IPTABLES_SAVE = "iptables_save"
    IPTABLES_RESTORE = "iptables_restore"
    IPTABLES_CREATE_CHAIN = "iptables_create_chain"
    IPTABLES_FLUSH_CHAIN = "iptables_flush_chain"
    IPTABLES_DELETE_CHAIN = "iptables_delete_chain"
    IPTABLES_ADD_RULE = "iptables_add_rule"
    IPTABLES_DELETE_RULE = "iptables_delete_rule"
    KILL_PROCESS = "kill_process"
    DISABLE_USER = "disable_user"
    ENABLE_USER = "enable_user"


class PrivilegeError(Exception):
    """Raised when privileged operation fails"""
    pass


class PrivilegeManager:
    """
    Manages privilege escalation for LoneWarrior.

    Supports three modes:
    1. NONE: Skip privileged operations (graceful degradation)
    2. HELPER: Use sudo with lw-privilege-helper
    3. ROOT: Direct execution (legacy, when running as root)
    """

    HELPER_PATH = "/usr/local/bin/lw-privilege-helper"
    ALLOWED_CHAINS = {"LONEWARRIOR_RATELIMIT", "LW_CONTAIN", "LW_BLOCK"}

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._level = self._detect_privilege_level()
        self._helper_available = self._check_helper_available()

        # Capability cache
        self._capabilities: Dict[str, bool] = {}
        self._detect_capabilities()

        logger.info(f"Privilege manager initialized: level={self._level.value}, "
                   f"helper_available={self._helper_available}")

    def _detect_privilege_level(self) -> PrivilegeLevel:
        """Detect current privilege level"""
        # Check if running as root
        if os.geteuid() == 0:
            return PrivilegeLevel.ROOT

        # Check if helper is available via sudo
        if self._check_helper_available():
            return PrivilegeLevel.HELPER

        return PrivilegeLevel.NONE

    def _check_helper_available(self) -> bool:
        """Check if privilege helper is available and configured"""
        if not Path(self.HELPER_PATH).exists():
            return False

        # Check if we can run it via sudo without password
        try:
            result = subprocess.run(
                ["sudo", "-n", self.HELPER_PATH, "--check"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _detect_capabilities(self):
        """Detect available capabilities"""
        self._capabilities = {
            'iptables': self._can_iptables(),
            'kill': self._can_kill_processes(),
            'user_mgmt': self._can_manage_users(),
        }

    def _can_iptables(self) -> bool:
        """Check if iptables operations are available"""
        if self._level == PrivilegeLevel.ROOT:
            return True
        if self._level == PrivilegeLevel.HELPER and self._helper_available:
            return True
        return False

    def _can_kill_processes(self) -> bool:
        """Check if process kill is available"""
        if self._level == PrivilegeLevel.ROOT:
            return True
        if self._level == PrivilegeLevel.HELPER and self._helper_available:
            return True
        # Can always kill own processes
        return True

    def _can_manage_users(self) -> bool:
        """Check if user management is available"""
        if self._level == PrivilegeLevel.ROOT:
            return True
        if self._level == PrivilegeLevel.HELPER and self._helper_available:
            return True
        return False

    @property
    def level(self) -> PrivilegeLevel:
        return self._level

    @property
    def capabilities(self) -> Dict[str, bool]:
        return self._capabilities.copy()

    def can_perform(self, operation: PrivilegedOperation) -> bool:
        """Check if an operation can be performed"""
        op_to_cap = {
            PrivilegedOperation.IPTABLES_BLOCK_IP: 'iptables',
            PrivilegedOperation.IPTABLES_UNBLOCK_IP: 'iptables',
            PrivilegedOperation.IPTABLES_SAVE: 'iptables',
            PrivilegedOperation.IPTABLES_RESTORE: 'iptables',
            PrivilegedOperation.IPTABLES_CREATE_CHAIN: 'iptables',
            PrivilegedOperation.IPTABLES_FLUSH_CHAIN: 'iptables',
            PrivilegedOperation.IPTABLES_DELETE_CHAIN: 'iptables',
            PrivilegedOperation.IPTABLES_ADD_RULE: 'iptables',
            PrivilegedOperation.IPTABLES_DELETE_RULE: 'iptables',
            PrivilegedOperation.KILL_PROCESS: 'kill',
            PrivilegedOperation.DISABLE_USER: 'user_mgmt',
            PrivilegedOperation.ENABLE_USER: 'user_mgmt',
        }
        cap = op_to_cap.get(operation)
        return self._capabilities.get(cap, False)

    def execute(self, operation: PrivilegedOperation,
                params: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Execute a privileged operation.

        Args:
            operation: The operation to perform
            params: Operation parameters (will be validated)

        Returns:
            Tuple of (success, message/error)
        """
        if not self.can_perform(operation):
            return False, f"Operation {operation.value} not available (insufficient privileges)"

        # Validate parameters
        try:
            validated_params = self._validate_params(operation, params)
        except ValueError as e:
            return False, f"Invalid parameters: {e}"

        # Execute based on privilege level
        if self._level == PrivilegeLevel.ROOT:
            return self._execute_direct(operation, validated_params)
        elif self._level == PrivilegeLevel.HELPER:
            return self._execute_via_helper(operation, validated_params)
        else:
            return False, "No privilege mechanism available"

    def _validate_params(self, operation: PrivilegedOperation,
                         params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate operation parameters - critical for security"""
        validated = {}

        if operation in (PrivilegedOperation.IPTABLES_BLOCK_IP,
                        PrivilegedOperation.IPTABLES_UNBLOCK_IP):
            # Validate IP address
            ip = params.get('ip')
            if not ip:
                raise ValueError("IP address required")
            validated['ip'] = validate_ip_address_or_raise(str(ip))

        elif operation == PrivilegedOperation.IPTABLES_RESTORE:
            rules = params.get('rules')
            if not rules or not isinstance(rules, str):
                raise ValueError("Rules data required")
            # Basic sanity check on rules
            if len(rules) > 1024 * 1024:  # 1MB max
                raise ValueError("Rules data too large")
            validated['rules'] = rules

        elif operation in (PrivilegedOperation.IPTABLES_CREATE_CHAIN,
                          PrivilegedOperation.IPTABLES_FLUSH_CHAIN,
                          PrivilegedOperation.IPTABLES_DELETE_CHAIN):
            chain = params.get('chain')
            if not chain or chain not in self.ALLOWED_CHAINS:
                raise ValueError(f"Invalid chain name. Allowed: {self.ALLOWED_CHAINS}")
            validated['chain'] = chain

        elif operation == PrivilegedOperation.IPTABLES_ADD_RULE:
            chain = params.get('chain')
            if chain not in self.ALLOWED_CHAINS:
                raise ValueError(f"Invalid chain name. Allowed: {self.ALLOWED_CHAINS}")
            validated['chain'] = chain

            rule_args = params.get('rule_args', [])
            if not isinstance(rule_args, list):
                raise ValueError("rule_args must be a list")
            # Validate each argument
            validated['rule_args'] = self._validate_iptables_args(rule_args)

        elif operation == PrivilegedOperation.KILL_PROCESS:
            pid = params.get('pid')
            if not isinstance(pid, int) or pid < 1:
                raise ValueError("Valid PID required")
            # Protect critical PIDs
            if pid == 1 or pid == os.getpid():
                raise ValueError("Cannot kill protected process")
            validated['pid'] = pid

            signal = params.get('signal', 15)  # SIGTERM default
            if signal not in (9, 15):  # Only SIGTERM or SIGKILL
                raise ValueError("Invalid signal")
            validated['signal'] = signal

        elif operation in (PrivilegedOperation.DISABLE_USER,
                          PrivilegedOperation.ENABLE_USER):
            username = params.get('username')
            if not username or not isinstance(username, str):
                raise ValueError("Username required")
            # Validate username format
            if not self._validate_username(username):
                raise ValueError("Invalid username format")
            # Protect critical users
            if username in ('root', 'lonewarrior', 'nobody'):
                raise ValueError(f"Cannot modify protected user: {username}")
            validated['username'] = username

        return validated

    def _validate_iptables_args(self, args: list) -> list:
        """Validate iptables rule arguments"""
        validated = []
        allowed_flags = {
            '-s', '-d', '-p', '-j', '-m', '--dport', '--sport',
            '--limit', '--limit-burst', '--state', '--ctstate',
            '-i', '-o', '--hashlimit', '--hashlimit-name',
            '--hashlimit-mode', '--hashlimit-burst'
        }
        allowed_targets = {'ACCEPT', 'DROP', 'REJECT', 'LOG', 'RETURN'}
        allowed_protocols = {'tcp', 'udp', 'icmp', 'all'}
        allowed_states = {'NEW', 'ESTABLISHED', 'RELATED', 'INVALID'}

        i = 0
        while i < len(args):
            arg = str(args[i])

            # Check for flag
            if arg.startswith('-'):
                if arg not in allowed_flags:
                    raise ValueError(f"Disallowed iptables flag: {arg}")
                validated.append(arg)

                # Handle flag value
                if i + 1 < len(args):
                    value = str(args[i + 1])

                    if arg in ('-s', '-d'):
                        # Validate IP/CIDR
                        value = validate_ip_address_or_raise(value.split('/')[0])
                        if '/' in str(args[i + 1]):
                            # Validate CIDR prefix
                            prefix = str(args[i + 1]).split('/')[1]
                            if not prefix.isdigit() or not (0 <= int(prefix) <= 128):
                                raise ValueError(f"Invalid CIDR prefix: {prefix}")
                            value = f"{value}/{prefix}"
                    elif arg == '-j':
                        if value not in allowed_targets:
                            raise ValueError(f"Disallowed target: {value}")
                    elif arg == '-p':
                        if value not in allowed_protocols:
                            raise ValueError(f"Disallowed protocol: {value}")
                    elif arg in ('--state', '--ctstate'):
                        for state in value.split(','):
                            if state not in allowed_states:
                                raise ValueError(f"Disallowed state: {state}")
                    elif arg in ('--dport', '--sport'):
                        if not value.isdigit() or not (1 <= int(value) <= 65535):
                            raise ValueError(f"Invalid port: {value}")

                    validated.append(value)
                    i += 1
            else:
                raise ValueError(f"Unexpected argument: {arg}")

            i += 1

        return validated

    def _validate_username(self, username: str) -> bool:
        """Validate username format"""
        import re
        # Standard Linux username format
        return bool(re.match(r'^[a-z_][a-z0-9_-]{0,31}$', username))

    def _execute_direct(self, operation: PrivilegedOperation,
                       params: Dict[str, Any]) -> Tuple[bool, str]:
        """Execute operation directly (when running as root)"""
        try:
            if operation == PrivilegedOperation.IPTABLES_BLOCK_IP:
                return self._iptables_block_ip(params['ip'])
            elif operation == PrivilegedOperation.IPTABLES_UNBLOCK_IP:
                return self._iptables_unblock_ip(params['ip'])
            elif operation == PrivilegedOperation.IPTABLES_SAVE:
                return self._iptables_save()
            elif operation == PrivilegedOperation.IPTABLES_RESTORE:
                return self._iptables_restore(params['rules'])
            elif operation == PrivilegedOperation.IPTABLES_CREATE_CHAIN:
                return self._iptables_chain_op('-N', params['chain'])
            elif operation == PrivilegedOperation.IPTABLES_FLUSH_CHAIN:
                return self._iptables_chain_op('-F', params['chain'])
            elif operation == PrivilegedOperation.IPTABLES_DELETE_CHAIN:
                return self._iptables_chain_op('-X', params['chain'])
            elif operation == PrivilegedOperation.IPTABLES_ADD_RULE:
                return self._iptables_add_rule(params['chain'], params['rule_args'])
            elif operation == PrivilegedOperation.KILL_PROCESS:
                return self._kill_process(params['pid'], params['signal'])
            elif operation == PrivilegedOperation.DISABLE_USER:
                return self._disable_user(params['username'])
            elif operation == PrivilegedOperation.ENABLE_USER:
                return self._enable_user(params['username'])
            else:
                return False, f"Unknown operation: {operation}"
        except Exception as e:
            logger.error(f"Direct execution failed: {e}")
            return False, str(e)

    def _execute_via_helper(self, operation: PrivilegedOperation,
                           params: Dict[str, Any]) -> Tuple[bool, str]:
        """Execute operation via privilege helper"""
        try:
            cmd = [
                "sudo", "-n", self.HELPER_PATH,
                "--operation", operation.value,
                "--params", json.dumps(params)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "Operation timed out"
        except Exception as e:
            logger.error(f"Helper execution failed: {e}")
            return False, str(e)

    # Direct execution methods (used when running as root)

    def _iptables_block_ip(self, ip: str) -> Tuple[bool, str]:
        """Block an IP address"""
        check = subprocess.run(
            ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
            capture_output=True, text=True, timeout=10
        )
        if check.returncode == 0:
            return True, "Rule already exists"

        result = subprocess.run(
            ['iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, f"Blocked {ip}"
        return False, result.stderr

    def _iptables_unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Unblock an IP address"""
        deleted = 0
        max_deletes = 50

        while deleted < max_deletes:
            check = subprocess.run(
                ['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, text=True, timeout=10
            )
            if check.returncode != 0:
                break

            result = subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return False, result.stderr
            deleted += 1

        return True, f"Unblocked {ip} ({deleted} rules removed)"

    def _iptables_save(self) -> Tuple[bool, str]:
        """Save iptables rules"""
        result = subprocess.run(
            ['iptables-save'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, result.stdout
        return False, result.stderr

    def _iptables_restore(self, rules: str) -> Tuple[bool, str]:
        """Restore iptables rules"""
        result = subprocess.run(
            ['iptables-restore'],
            input=rules,
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, "Rules restored"
        return False, result.stderr

    def _iptables_chain_op(self, op: str, chain: str) -> Tuple[bool, str]:
        """Chain operation (create/flush/delete)"""
        result = subprocess.run(
            ['iptables', op, chain],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, f"Chain {chain} {op}"
        # Chain might already exist/not exist
        if "already exist" in result.stderr or "No chain" in result.stderr:
            return True, result.stderr
        return False, result.stderr

    def _iptables_add_rule(self, chain: str, rule_args: list) -> Tuple[bool, str]:
        """Add iptables rule"""
        cmd = ['iptables', '-A', chain] + rule_args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True, "Rule added"
        return False, result.stderr

    def _kill_process(self, pid: int, signal: int) -> Tuple[bool, str]:
        """Kill a process"""
        import signal as sig
        try:
            os.kill(pid, signal)
            return True, f"Sent signal {signal} to PID {pid}"
        except ProcessLookupError:
            return True, f"Process {pid} already terminated"
        except PermissionError:
            return False, f"Permission denied to kill PID {pid}"

    def _disable_user(self, username: str) -> Tuple[bool, str]:
        """Disable a user account"""
        result = subprocess.run(
            ['usermod', '-L', '-e', '1', username],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, f"User {username} disabled"
        return False, result.stderr

    def _enable_user(self, username: str) -> Tuple[bool, str]:
        """Enable a user account"""
        result = subprocess.run(
            ['usermod', '-U', '-e', '', username],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, f"User {username} enabled"
        return False, result.stderr


# Singleton instance
_privilege_manager: Optional[PrivilegeManager] = None


def get_privilege_manager(config: Optional[Dict[str, Any]] = None) -> PrivilegeManager:
    """Get or create the privilege manager singleton"""
    global _privilege_manager
    if _privilege_manager is None:
        _privilege_manager = PrivilegeManager(config)
    return _privilege_manager
