"""
User Responder - User account management for security response
"""

import logging
import subprocess
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Action, ActionType, ActionStatus, Snapshot
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class UserResponder:
    """
    Handles user account management for security response.
    
    Features:
    - Disable user accounts temporarily
    - Lock user accounts
    - Terminate user sessions
    - SSH key revocation
    """
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Track disabled users for re-enabling (only users we disabled)
        self.disabled_users: Dict[str, datetime] = {}
        
        # System users that should never be modified
        self.protected_users = {'root', 'nobody', 'www-data', 'daemon', 'bin', 'sys', 'sync', 'games', 'man', 'lp', 'mail', 'news', 'uucp', 'proxy', 'backup', 'list', 'irc', 'gnats', 'systemd-network', 'systemd-resolve', 'messagebus', 'sshd', 'ntp', 'mysql', 'postgres', 'redis', 'mongodb', 'nginx', 'apache', 'httpd'}
        
        # Subscribe to events
        self._event_handlers = [
            ('disable_user', self.handle_disable_request),
            ('enable_user', self.handle_enable_request),
            ('kill_user_sessions', self.handle_session_kill)
        ]
        for event_type, handler in self._event_handlers:
            self.event_bus.subscribe(event_type, handler)
    
    def start(self):
        """Start user responder"""
        logger.info("User responder started")
    
    def stop(self):
        """Stop user responder"""
        # Re-enable only users WE disabled (not users who were disabled before service start)
        for username in list(self.disabled_users.keys()):
            self.enable_user(username)
        
        # Unsubscribe from events
        for event_type, handler in self._event_handlers:
            try:
                self.event_bus.unsubscribe(event_type, handler)
            except Exception:
                pass
        
        logger.info("User responder stopped")
    
    def handle_disable_request(self, event):
        """Handle user disable request"""
        data = event.data
        username = data.get('username')
        detection_id = data.get('detection_id')
        duration = data.get('duration', 3600)  # Default 1 hour
        
        if username:
            self.disable_user(username, detection_id, duration)
    
    def handle_enable_request(self, event):
        """Handle user enable request"""
        data = event.data
        username = data.get('username')
        
        if username:
            self.enable_user(username)
    
    def handle_session_kill(self, event):
        """Handle session termination request"""
        data = event.data
        username = data.get('username')
        
        if username:
            self.terminate_user_sessions(username)
    
    def disable_user(self, username: str, detection_id: Optional[int] = None,
                    duration_seconds: int = 3600) -> bool:
        """
        Disable a user account temporarily.
        
        Args:
            username: User to disable
            detection_id: Associated detection
            duration_seconds: How long to keep disabled
            
        Returns:
            True if successful
        """
        if username in self.protected_users:
            logger.warning(f"Refusing to disable system user: {username}")
            return False
        
        logger.warning(f"🔒 Disabling user: {username}")
        
        # Create snapshot of user state
        snapshot = self._create_user_snapshot(username)
        snapshot_id = self.db.insert_snapshot(snapshot)
        
        # Record action
        action = Action(
            action_type=ActionType.USER_DISABLE.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=detection_id,
            target=username,
            parameters={'duration': duration_seconds},
            snapshot_id=snapshot_id
        )
        action_id = self.db.insert_action(action)
        
        try:
            # Lock the user account
            result = subprocess.run(
                ['usermod', '-L', username],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                raise Exception(f"usermod failed: {result.stderr}")
            
            # Also expire the account
            chage_result = subprocess.run(
                ['chage', '-E', '0', username],
                capture_output=True, text=True, timeout=10
            )
            if chage_result.returncode != 0:
                logger.warning(f"chage command failed: {chage_result.stderr}")
            
            # Track for re-enabling
            self.disabled_users[username] = datetime.now(timezone.utc)
            
            self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                 result=f"Disabled for {duration_seconds}s")
            
            logger.warning(f"✅ User {username} disabled")
            
            # Publish event
            self.event_bus.publish(
                'user_disabled',
                {'username': username, 'duration': duration_seconds},
                EventPriority.HIGH,
                'UserResponder'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to disable user {username}: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            return False
    
    def enable_user(self, username: str) -> bool:
        """
        Re-enable a disabled user account.
        
        Args:
            username: User to enable
            
        Returns:
            True if successful
        """
        logger.info(f"🔓 Re-enabling user: {username}")
        
        action = Action(
            action_type=ActionType.USER_ENABLE.value,
            status=ActionStatus.EXECUTING.value,
            target=username,
            parameters={}
        )
        action_id = self.db.insert_action(action)
        
        try:
            # Unlock the account
            subprocess.run(
                ['usermod', '-U', username],
                capture_output=True, timeout=10
            )
            
            # Remove expiry
            subprocess.run(
                ['chage', '-E', '-1', username],
                capture_output=True, timeout=10
            )
            
            if username in self.disabled_users:
                del self.disabled_users[username]
            
            self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                 result="User enabled")
            
            logger.info(f"✅ User {username} enabled")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable user {username}: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            return False
    
    def terminate_user_sessions(self, username: str) -> int:
        """
        Terminate all sessions for a user.
        
        Note: Will refuse to terminate sessions for system users.
        Args:
            username: User whose sessions to terminate
            
        Returns:
            Number of sessions terminated
        """
        # Protect system users
        if username in self.protected_users:
            logger.warning(f"Refusing to terminate sessions for system user: {username}")
            return 0
        
        logger.warning(f"Terminating sessions for user: {username}")
        
        terminated = 0
        
        try:
            # Kill all user processes
            result = subprocess.run(
                ['pkill', '-u', username],
                capture_output=True, timeout=10
            )
            
            # Count terminated (exit code 0 means something was killed)
            if result.returncode == 0:
                # Get rough count
                result = subprocess.run(
                    ['pgrep', '-u', username, '-c'],
                    capture_output=True, text=True, timeout=5
                )
                terminated = 1  # At least 1
            
            logger.info(f"Terminated sessions for {username}")
            
        except Exception as e:
            logger.error(f"Error terminating sessions for {username}: {e}")
        
        return terminated
    
    def revoke_ssh_keys(self, username: str) -> bool:
        """
        Revoke SSH keys for a user by renaming authorized_keys.
        
        Args:
            username: User whose keys to revoke
            
        Returns:
            True if successful
        """
        import os
        from pathlib import Path
        
        try:
            # Get user's home directory
            result = subprocess.run(
                ['getent', 'passwd', username],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode != 0:
                return False
            
            # Parse home directory safely with bounds checking
            passwd_parts = result.stdout.strip().split(':')
            if len(passwd_parts) < 6:
                logger.error(f"Invalid passwd entry for user {username}")
                return False
            
            home_dir = passwd_parts[5]
            if not home_dir:
                logger.error(f"Empty home directory for user {username}")
                return False
            
            ssh_dir = Path(home_dir) / '.ssh'
            authorized_keys = ssh_dir / 'authorized_keys'
            
            if authorized_keys.exists():
                # Rename to .revoked with timestamp
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
                revoked_path = ssh_dir / f'authorized_keys.revoked_{timestamp}'
                authorized_keys.rename(revoked_path)
                
                logger.warning(f"Revoked SSH keys for {username}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to revoke SSH keys for {username}: {e}")
            return False
    
    def _create_user_snapshot(self, username: str) -> Snapshot:
        """Create snapshot of user's current state"""
        try:
            result = subprocess.run(
                ['getent', 'passwd', username],
                capture_output=True, text=True, timeout=5
            )
            passwd_entry = result.stdout.strip()
            
            result = subprocess.run(
                ['getent', 'shadow', username],
                capture_output=True, text=True, timeout=5
            )
            shadow_entry = result.stdout.strip()
            
        except Exception:
            passwd_entry = ""
            shadow_entry = ""
        
        return Snapshot(
            snapshot_type='user_state',
            state_data={
                'username': username,
                'passwd': passwd_entry,
                'shadow': shadow_entry,
                'enabled': True
            }
        )
