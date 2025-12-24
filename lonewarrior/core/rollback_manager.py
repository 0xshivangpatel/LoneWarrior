"""
Rollback Manager - Automatic rollback on health check failure
"""

import logging
import subprocess
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Snapshot, Action, ActionStatus
from lonewarrior.core.event_bus import EventBus, EventPriority


logger = logging.getLogger(__name__)


class RollbackManager:
    """
    Manages automatic rollback of actions on health check failure.
    
    Features:
    - Restore iptables from snapshot
    - Track rollback history
    - Emergency rollback on critical failure
    """
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        
        # Settings
        self.auto_rollback_enabled = config.get('health', {}).get('auto_rollback', True)
        
        # Subscribe to health events
        self.event_bus.subscribe('health_check_failed', self.handle_health_failure)
        self.event_bus.subscribe('emergency_rollback', self.handle_emergency_rollback)
    
    def start(self):
        """Start rollback manager"""
        logger.info("Rollback manager started")
    
    def stop(self):
        """Stop rollback manager"""
        logger.info("Rollback manager stopped")
    
    def handle_health_failure(self, event):
        """Handle health check failure"""
        if not self.auto_rollback_enabled:
            logger.warning("Auto-rollback disabled, skipping")
            return
        
        data = event.data
        failed_checks = data.get('failed_checks', [])
        
        logger.critical(f"Health check failed: {failed_checks}")
        logger.critical("🔄 Initiating automatic rollback...")
        
        self.rollback_recent_actions()
    
    def handle_emergency_rollback(self, event):
        """Handle emergency rollback request"""
        logger.critical("🚨 EMERGENCY ROLLBACK REQUESTED")
        self.rollback_all()
    
    def rollback_recent_actions(self, max_actions: int = 10) -> int:
        """
        Rollback recent actions that have snapshots.
        
        Args:
            max_actions: Maximum number of actions to rollback
            
        Returns:
            Number of actions rolled back
        """
        # Get recent successful actions with snapshots
        actions = self.db.get_actions(limit=max_actions, status=ActionStatus.SUCCESS.value)
        
        rolled_back = 0
        for action in actions:
            if action.rolled_back:
                continue
            
            if action.snapshot_id:
                if self.rollback_action(action):
                    rolled_back += 1
        
        logger.info(f"Rolled back {rolled_back} actions")
        return rolled_back
    
    def rollback_action(self, action: Action) -> bool:
        """
        Rollback a single action using its snapshot.
        
        Args:
            action: Action to rollback
            
        Returns:
            True if rollback successful
        """
        if not action.snapshot_id:
            logger.warning(f"Action {action.id} has no snapshot, cannot rollback")
            return False
        
        snapshot = self.db.get_snapshot(action.snapshot_id)
        if not snapshot:
            logger.error(f"Snapshot {action.snapshot_id} not found")
            return False
        
        logger.info(f"Rolling back action {action.id} ({action.action_type})")
        
        try:
            if snapshot.snapshot_type == 'iptables':
                self._restore_iptables(snapshot)
            elif snapshot.snapshot_type == 'iptables_containment':
                self._restore_iptables(snapshot)
            elif snapshot.snapshot_type == 'user_state':
                self._restore_user_state(snapshot)
            else:
                logger.warning(f"Unknown snapshot type: {snapshot.snapshot_type}")
                return False
            
            # Mark action as rolled back
            self.db.update_action(action.id, action.status, rolled_back=True)
            
            logger.info(f"✅ Rolled back action {action.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback action {action.id}: {e}")
            return False
    
    def rollback_all(self) -> bool:
        """
        Emergency: Clear ALL agent-added iptables rules.
        
        Returns:
            True if successful
        """
        logger.critical("🚨 Rolling back ALL iptables changes")
        
        try:
            # Remove our custom chains
            chains = ['LONEWARRIOR_CONTAIN', 'LONEWARRIOR_RATELIMIT', 'LONEWARRIOR_BLOCK']
            
            for chain in chains:
                # First remove references
                self._remove_chain_references(chain)
                # Then flush and delete
                subprocess.run(['iptables', '-F', chain], 
                              capture_output=True, timeout=10)
                subprocess.run(['iptables', '-X', chain], 
                              capture_output=True, timeout=10)
            
            # Remove any rules with our comment marker
            self._remove_marked_rules()
            
            logger.critical("✅ Emergency rollback complete")
            
            # Publish event
            self.event_bus.publish(
                'emergency_rollback_complete',
                {},
                EventPriority.CRITICAL,
                'RollbackManager'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Emergency rollback failed: {e}")
            return False
    
    def _restore_iptables(self, snapshot: Snapshot):
        """Restore iptables from snapshot"""
        rules = snapshot.state_data.get('rules', '')
        
        if not rules:
            logger.warning("Empty iptables snapshot, clearing our rules instead")
            self.rollback_all()
            return
        
        try:
            # Restore rules using stdin (iptables-restore reads from stdin, not file path)
            result = subprocess.run(
                ['iptables-restore'],
                input=rules,
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                raise Exception(f"iptables-restore failed: {result.stderr}")
            
            logger.info("iptables rules restored from snapshot")
            
        except Exception as e:
            logger.error(f"Failed to restore iptables: {e}")
            raise
    
    def _restore_user_state(self, snapshot: Snapshot):
        """Restore user state from snapshot"""
        user = snapshot.state_data.get('username')
        was_enabled = snapshot.state_data.get('enabled', True)
        
        if user and was_enabled:
            # Re-enable user
            subprocess.run(['usermod', '-U', user], capture_output=True, timeout=10)
            logger.info(f"Re-enabled user: {user}")
    
    def _remove_chain_references(self, chain: str):
        """Remove all references to a chain from other chains"""
        for parent in ['INPUT', 'OUTPUT', 'FORWARD']:
            try:
                subprocess.run(
                    ['iptables', '-D', parent, '-j', chain],
                    capture_output=True, timeout=10
                )
            except Exception:
                pass
    
    def _remove_marked_rules(self):
        """Remove rules marked with our comment"""
        # List all rules with comments
        try:
            result = subprocess.run(
                ['iptables', '-L', '-n', '--line-numbers'],
                capture_output=True, text=True, timeout=10
            )
            
            # Parse and remove rules with LONEWARRIOR in comment
            # This is a simplified approach - production would be more robust
            for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
                result = subprocess.run(
                    ['iptables', '-S', chain],
                    capture_output=True, text=True, timeout=10
                )
                
                for line in result.stdout.split('\n'):
                    if 'LONEWARRIOR' in line or 'lonewarrior' in line:
                        # Extract rule and delete it
                        try:
                            # Convert -A to -D
                            delete_rule = line.replace('-A ', '-D ', 1)
                            subprocess.run(
                                ['iptables'] + delete_rule.split()[1:],
                                capture_output=True, timeout=10
                            )
                        except:
                            pass
        except Exception as e:
            logger.error(f"Error removing marked rules: {e}")
    
    def create_restore_script(self, path: str = '/tmp/lonewarrior_restore.sh') -> str:
        """
        Create a shell script that can restore the current state.
        
        Args:
            path: Path to save script
            
        Returns:
            Path to created script
        """
        try:
            result = subprocess.run(['iptables-save'], capture_output=True, 
                                   text=True, timeout=10)
            rules = result.stdout
            
            # Use a unique heredoc delimiter to prevent collision
            script = f"""#!/bin/bash
# LoneWarrior Emergency Restore Script
# Generated: {datetime.now(timezone.utc).isoformat()}

echo "Restoring iptables rules..."
cat << 'EOF_LONEWARRIOR_RESTORE_RULES' | iptables-restore
{rules}
EOF_LONEWARRIOR_RESTORE_RULES

echo "Done!"
"""
            
            with open(path, 'w') as f:
                f.write(script)
            
            import os
            os.chmod(path, 0o755)
            
            logger.info(f"Created restore script: {path}")
            return path
            
        except Exception as e:
            logger.error(f"Failed to create restore script: {e}")
            return ""
