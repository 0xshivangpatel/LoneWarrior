"""
Containment Mode - Full system containment for active attacks
"""

import logging
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta

from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Action, ActionType, ActionStatus, Snapshot
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class ContainmentMode:
    """
    Full containment mode for active attack response.
    
    Actions taken:
    - Block all outbound traffic except whitelisted IPs
    - Rate limit inbound connections
    - Pause new SSH logins (optional)
    - Log all blocked traffic for forensics
    """
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Containment settings
        self.whitelist_ips = config.get('containment', {}).get('whitelist_ips', [])
        self.whitelist_domains = config.get('containment', {}).get('whitelist_domains', [])
        self.pause_ssh = config.get('containment', {}).get('pause_ssh_logins', True)
        self.inbound_rate_limit = config.get('containment', {}).get('inbound_rate_limit', 10)
        
        # Track active rules for cleanup
        self.active_rules: List[str] = []
        
        # Track whether SSH was actually paused (for proper resume)
        self._ssh_paused = False
        
        # Subscribe to containment triggers
        self._event_handlers = [
            ('trigger_containment_mode', self.handle_containment_trigger),
            ('disable_containment_mode', self.handle_disable_trigger)
        ]
        for event_type, handler in self._event_handlers:
            self.event_bus.subscribe(event_type, handler)
    
    def start(self):
        """Start containment mode handler"""
        logger.info("Containment mode handler started")
    
    def stop(self):
        """Stop and cleanup containment mode"""
        if self.state.is_containment_active():
            self.disable_containment()
        
        # Unsubscribe from events
        for event_type, handler in self._event_handlers:
            try:
                self.event_bus.unsubscribe(event_type, handler)
            except Exception:
                pass
        
        logger.info("Containment mode handler stopped")
    
    def handle_containment_trigger(self, event):
        """Handle containment mode trigger event"""
        data = event.data
        reason = data.get('reason', 'High confidence attack detected')
        duration = data.get('duration', self.config['containment']['default_duration'])
        detection_id = data.get('detection_id')
        
        self.enable_containment(reason, duration, detection_id)
    
    def handle_disable_trigger(self, event):
        """Handle containment disable event"""
        self.disable_containment()
    
    def enable_containment(self, reason: str, duration_seconds: int, 
                          detection_id: Optional[int] = None) -> bool:
        """
        Enable full containment mode.
        
        Args:
            reason: Reason for enabling containment
            duration_seconds: How long containment should last
            detection_id: Associated detection ID
            
        Returns:
            True if containment was successfully enabled
        """
        if self.state.is_containment_active():
            logger.warning("Containment already active, extending duration")
            self.state.extend_containment(duration_seconds)
            return True
        
        logger.critical(f"🔒 ENABLING CONTAINMENT MODE: {reason}")
        
        # Create snapshot before making changes
        snapshot = self._create_iptables_snapshot()
        snapshot_id = self.db.insert_snapshot(snapshot)
        
        # Record action
        action = Action(
            action_type=ActionType.CONTAINMENT_MODE_ENABLE.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=detection_id,
            target="system",
            parameters={
                'reason': reason,
                'duration': duration_seconds,
                'whitelist_ips': self.whitelist_ips
            },
            snapshot_id=snapshot_id
        )
        action_id = self.db.insert_action(action)
        
        try:
            # 1. Block all outbound traffic except whitelist
            if not self._block_outbound_traffic():
                raise Exception("Failed to block outbound traffic")
            
            # 2. Rate limit inbound connections
            if not self._apply_inbound_rate_limit():
                logger.warning("Failed to apply inbound rate limit, continuing")
            
            # 3. Optionally pause SSH logins
            if self.pause_ssh:
                if self._pause_ssh_logins():
                    self._ssh_paused = True
            
            # Update state
            self.state.enable_containment_mode(duration_seconds)
            
            # Update action status
            self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                 result=f"Containment enabled for {duration_seconds}s")
            
            logger.critical(f"✅ Containment mode ACTIVE for {duration_seconds} seconds")
            
            # Publish event
            self.event_bus.publish(
                'containment_enabled',
                {'reason': reason, 'duration': duration_seconds, 'action_id': action_id},
                EventPriority.CRITICAL,
                'ContainmentMode'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable containment: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            # Rollback any partial changes
            self._rollback_rules()
            return False
    
    def disable_containment(self) -> bool:
        """
        Disable containment mode and restore normal operation.
        
        Returns:
            True if containment was successfully disabled
        """
        if not self.state.is_containment_active():
            logger.warning("Containment not active, nothing to disable")
            return True
        
        logger.info("🔓 DISABLING CONTAINMENT MODE")
        
        # Record action
        action = Action(
            action_type=ActionType.CONTAINMENT_MODE_DISABLE.value,
            status=ActionStatus.EXECUTING.value,
            target="system",
            parameters={}
        )
        action_id = self.db.insert_action(action)
        
        try:
            # Remove all containment rules
            self._rollback_rules()
            
            # Resume SSH if it was actually paused (based on state, not config)
            if self._ssh_paused:
                self._resume_ssh_logins()
                self._ssh_paused = False
            
            # Update state
            self.state.disable_containment_mode()
            
            # Update action status
            self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                 result="Containment disabled")
            
            logger.info("✅ Containment mode DISABLED - normal operation restored")
            
            # Publish event
            self.event_bus.publish(
                'containment_disabled',
                {'action_id': action_id},
                EventPriority.HIGH,
                'ContainmentMode'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to disable containment: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            return False
    
    def _block_outbound_traffic(self) -> bool:
        """Block all outbound traffic except whitelisted IPs"""
        rules_added = []  # Track rules for rollback on failure
        try:
            # Create containment chain
            if not self._run_iptables(['-N', 'LONEWARRIOR_CONTAIN']):
                raise Exception("Failed to create LONEWARRIOR_CONTAIN chain")
            self.active_rules.append('chain:LONEWARRIOR_CONTAIN')
            rules_added.append('chain:LONEWARRIOR_CONTAIN')
            
            # Allow loopback
            if not self._run_iptables(['-A', 'LONEWARRIOR_CONTAIN', '-o', 'lo', '-j', 'ACCEPT']):
                raise Exception("Failed to add loopback rule")
            
            # Allow established connections
            if not self._run_iptables(['-A', 'LONEWARRIOR_CONTAIN', '-m', 'state', 
                              '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']):
                raise Exception("Failed to add established connections rule")
            
            # Allow whitelisted IPs
            for ip in self.whitelist_ips:
                if not self._run_iptables(['-A', 'LONEWARRIOR_CONTAIN', '-d', ip, '-j', 'ACCEPT']):
                    logger.warning(f"Failed to whitelist {ip}, continuing")
                else:
                    logger.info(f"Whitelisted outbound: {ip}")
            
            # Allow DNS only to whitelisted IPs (not any destination)
            # This prevents DNS-based exfiltration
            dns_servers = self.config.get('containment', {}).get('allowed_dns_servers', [])
            if dns_servers:
                for dns_ip in dns_servers:
                    self._run_iptables(['-A', 'LONEWARRIOR_CONTAIN', '-p', 'udp', 
                                      '-d', dns_ip, '--dport', '53', '-j', 'ACCEPT'])
                    self._run_iptables(['-A', 'LONEWARRIOR_CONTAIN', '-p', 'tcp', 
                                      '-d', dns_ip, '--dport', '53', '-j', 'ACCEPT'])
            else:
                # If no DNS servers configured, allow to whitelisted IPs only
                logger.warning("No allowed_dns_servers configured, DNS to whitelisted IPs only")
            
            # Log and drop everything else
            self._run_iptables(['-A', 'LONEWARRIOR_CONTAIN', '-j', 'LOG', 
                              '--log-prefix', '[LONEWARRIOR_BLOCKED] '])
            if not self._run_iptables(['-A', 'LONEWARRIOR_CONTAIN', '-j', 'DROP']):
                raise Exception("Failed to add DROP rule")
            
            # Insert chain into OUTPUT
            if not self._run_iptables(['-I', 'OUTPUT', '1', '-j', 'LONEWARRIOR_CONTAIN']):
                raise Exception("Failed to insert chain into OUTPUT")
            self.active_rules.append('jump:OUTPUT:LONEWARRIOR_CONTAIN')
            rules_added.append('jump:OUTPUT:LONEWARRIOR_CONTAIN')
            
            logger.warning("Outbound traffic blocked (except whitelist)")
            return True
        except Exception as e:
            logger.error(f"Failed to block outbound traffic: {e}")
            # Rollback partial rules
            for rule in reversed(rules_added):
                try:
                    if rule in self.active_rules:
                        self.active_rules.remove(rule)
                    self._cleanup_rule(rule)
                except Exception:
                    pass
            return False
    
    def _apply_inbound_rate_limit(self) -> bool:
        """Apply rate limiting to inbound connections"""
        rules_added = []  # Track rules for rollback on failure
        try:
            # Create rate limit chain
            if not self._run_iptables(['-N', 'LONEWARRIOR_RATELIMIT']):
                raise Exception("Failed to create LONEWARRIOR_RATELIMIT chain")
            self.active_rules.append('chain:LONEWARRIOR_RATELIMIT')
            rules_added.append('chain:LONEWARRIOR_RATELIMIT')
            
            # Rate limit new connections
            limit = str(self.inbound_rate_limit)
            if not self._run_iptables(['-A', 'LONEWARRIOR_RATELIMIT', '-p', 'tcp', 
                              '-m', 'state', '--state', 'NEW',
                              '-m', 'limit', '--limit', f'{limit}/minute',
                              '--limit-burst', str(int(self.inbound_rate_limit * 2)),
                              '-j', 'ACCEPT']):
                raise Exception("Failed to add rate limit ACCEPT rule")
            
            # Drop excess
            if not self._run_iptables(['-A', 'LONEWARRIOR_RATELIMIT', '-p', 'tcp',
                              '-m', 'state', '--state', 'NEW', '-j', 'DROP']):
                raise Exception("Failed to add rate limit DROP rule")
            
            # Accept all other traffic
            if not self._run_iptables(['-A', 'LONEWARRIOR_RATELIMIT', '-j', 'ACCEPT']):
                raise Exception("Failed to add rate limit default ACCEPT rule")
            
            # Insert into INPUT
            if not self._run_iptables(['-I', 'INPUT', '1', '-j', 'LONEWARRIOR_RATELIMIT']):
                raise Exception("Failed to insert ratelimit chain into INPUT")
            self.active_rules.append('jump:INPUT:LONEWARRIOR_RATELIMIT')
            rules_added.append('jump:INPUT:LONEWARRIOR_RATELIMIT')
            
            logger.warning(f"Inbound rate limited to {limit}/minute")
            return True
        except Exception as e:
            logger.error(f"Failed to apply inbound rate limit: {e}")
            # Rollback partial rules to prevent leak
            for rule in reversed(rules_added):
                try:
                    if rule in self.active_rules:
                        self.active_rules.remove(rule)
                    self._cleanup_rule(rule)
                except Exception:
                    pass
            return False
    
    def _pause_ssh_logins(self) -> bool:
        """Pause new SSH logins (existing sessions continue)"""
        try:
            # Block new SSH connections
            self._run_iptables(['-I', 'INPUT', '1', '-p', 'tcp', '--dport', '22',
                              '-m', 'state', '--state', 'NEW', '-j', 'DROP'])
            self.active_rules.append('rule:INPUT:ssh_block')
            
            logger.warning("New SSH logins paused")
            return True
        except Exception as e:
            logger.error(f"Failed to pause SSH logins: {e}")
            return False
    
    def _resume_ssh_logins(self):
        """Resume SSH logins"""
        try:
            self._run_iptables(['-D', 'INPUT', '-p', 'tcp', '--dport', '22',
                              '-m', 'state', '--state', 'NEW', '-j', 'DROP'])
            logger.info("SSH logins resumed")
        except Exception as e:
            logger.error(f"Failed to resume SSH: {e}")
    
    def _rollback_rules(self):
        """Remove all containment rules"""
        # Remove jump rules first
        for rule in reversed(self.active_rules):
            try:
                if rule.startswith('jump:'):
                    _, chain, target = rule.split(':')
                    self._run_iptables(['-D', chain, '-j', target])
                elif rule.startswith('rule:'):
                    # Handle specific rule removal - for now just log it
                    logger.debug(f"Would remove rule: {rule}")
                    # Remove from active_rules but don't try to remove complex rules
                    self.active_rules.remove(rule)
                    continue
                elif rule.startswith('chain:'):
                    chain = rule.split(':')[1]
                    # Flush and delete chain
                    self._run_iptables(['-F', chain])
                    self._run_iptables(['-X', chain])
            except Exception as e:
                logger.error(f"Failed to remove rule {rule}: {e}")
        
        # Only clear rules that were actually applied
        for rule in list(self.active_rules):
            if rule.startswith('rule:'):
                self.active_rules.remove(rule)
        
        logger.info("Containment rules removed")
    
    def _run_iptables(self, args: List[str]) -> bool:
        """Run iptables command"""
        cmd = ['iptables'] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.error(f"iptables error: {result.stderr}")
                return False
            return True
        except Exception as e:
            logger.error(f"iptables exception: {e}")
            return False
    
    def _create_iptables_snapshot(self) -> Snapshot:
        """Create snapshot of current iptables rules"""
        try:
            result = subprocess.run(['iptables-save'], capture_output=True, 
                                   text=True, timeout=10)
            rules = result.stdout
        except Exception as e:
            logger.error(f"Failed to snapshot iptables: {e}")
            rules = ""
        
        return Snapshot(
            snapshot_type='iptables_containment',
            state_data={'rules': rules, 'active_rules': self.active_rules.copy()}
        )
