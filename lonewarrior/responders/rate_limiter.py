"""
Rate Limiter - Network rate limiting for attack mitigation

Security Design:
- Uses privilege helper for iptables operations when not running as root
- Gracefully degrades when privileges are unavailable
- All IP addresses are validated before use
"""

import logging
import os
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from lonewarrior.utils.validators import validate_ip_address_or_raise
from lonewarrior.utils.privilege_helper import (
    get_privilege_manager,
    PrivilegedOperation,
    PrivilegeLevel
)

from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Action, ActionType, ActionStatus
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Implements network rate limiting using iptables.

    Features:
    - Per-IP rate limiting
    - Port-based rate limiting
    - Protocol-specific limits
    - Automatic expiry
    - Graceful degradation when privileges unavailable
    """

    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager

        # Privilege manager for secure privilege escalation
        self.priv_mgr = get_privilege_manager(config)

        # Check if rate limiting is available
        self.enabled = self.priv_mgr.can_perform(PrivilegedOperation.IPTABLES_ADD_RULE)

        # Rate limit settings
        self.default_rate = config.get('actions', {}).get('rate_limit', {}).get('default_rate', 10)
        self.default_burst = config.get('actions', {}).get('rate_limit', {}).get('default_burst', 20)

        # Track active rate limits
        self.active_limits: Dict[str, Dict[str, Any]] = {}

        # Track port-based rate limits
        self.active_port_limits: Dict[str, Dict[str, Any]] = {}

        # Subscribe to events
        self._event_handlers = [
            ('apply_rate_limit', self.handle_rate_limit_request),
            ('remove_rate_limit', self.handle_remove_request)
        ]
        for event_type, handler in self._event_handlers:
            self.event_bus.subscribe(event_type, handler)

    def start(self):
        """Start rate limiter"""
        if not self.enabled:
            logger.warning(
                "Rate limiter DISABLED - insufficient privileges. "
                "Run as root or configure sudo for lw-privilege-helper. "
                "See docs/INSTALLATION.md for privilege separation setup."
            )
            return

        try:
            self._init_rate_limit_chain()
            logger.info("Rate limiter started")
        except Exception as e:
            # Graceful degradation: disable rate limiting if init fails
            if "Permission denied" in str(e) or "you must be root" in str(e):
                logger.warning(
                    f"Rate limiter disabled due to permission error: {e}. "
                    "Rate limiting features will be unavailable."
                )
                self.enabled = False
            else:
                # Re-raise unexpected errors
                raise
    
    def stop(self):
        """Stop and cleanup rate limiter"""
        self._cleanup_all_limits()
        
        # Unsubscribe from events
        for event_type, handler in self._event_handlers:
            try:
                self.event_bus.unsubscribe(event_type, handler)
            except Exception:
                pass
        
        logger.info("Rate limiter stopped")
    
    def handle_rate_limit_request(self, event):
        """Handle rate limit request"""
        data = event.data
        ip = data.get('ip')
        rate = data.get('rate', self.default_rate)
        burst = data.get('burst', self.default_burst)
        duration = data.get('duration', 3600)
        detection_id = data.get('detection_id')
        
        if ip:
            self.apply_rate_limit(ip, rate, burst, duration, detection_id)
    
    def handle_remove_request(self, event):
        """Handle rate limit removal"""
        data = event.data
        ip = data.get('ip')
        
        if ip:
            self.remove_rate_limit(ip)
    
    def apply_rate_limit(self, ip: str, rate: int = None, burst: int = None,
                        duration_seconds: int = 3600,
                        detection_id: Optional[int] = None,
                        protocol: str = 'tcp') -> bool:
        """
        Apply rate limiting to an IP address.

        Args:
            ip: IP address to rate limit
            rate: Connections per minute
            burst: Burst allowance
            duration_seconds: How long to enforce limit
            detection_id: Associated detection
            protocol: Protocol to limit (tcp or udp)

        Returns:
            True if successful
        """
        # Check if rate limiting is enabled
        if not self.enabled:
            logger.debug(f"Rate limiting skipped for {ip} - feature disabled")
            return False

        # Validate IP address
        try:
            validated_ip = validate_ip_address_or_raise(ip)
        except ValueError as e:
            logger.error(f"Invalid IP address for rate limiting: {e}")
            return False
        
        rate = rate or self.default_rate
        burst = burst or self.default_burst
        
        logger.warning(f"⏱️ Rate limiting {validated_ip}: {rate}/min (burst {burst})")
        
        action = Action(
            action_type=ActionType.RATE_LIMIT.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=detection_id,
            target=ip,
            parameters={
                'rate': rate,
                'burst': burst,
                'duration': duration_seconds
            }
        )
        action_id = self.db.insert_action(action)
        
        try:
            # Add rate limit rule
            self._run_iptables([
                '-A', 'LONEWARRIOR_RATELIMIT',
                '-s', validated_ip,
                '-p', protocol,
                '-m', 'limit', '--limit', f'{rate}/minute', '--limit-burst', str(burst),
                '-j', 'ACCEPT'
            ])
            
            # Drop excess from this IP
            self._run_iptables([
                '-A', 'LONEWARRIOR_RATELIMIT',
                '-s', validated_ip,
                '-j', 'DROP'
            ])
            
            # Track limit
            self.active_limits[validated_ip] = {
                'rate': rate,
                'burst': burst,
                'protocol': protocol,
                'applied_at': datetime.now(timezone.utc),
                'expires_at': datetime.now(timezone.utc).timestamp() + duration_seconds,
                'action_id': action_id
            }
            
            self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                 result=f"Rate limited at {rate}/min")
            
            logger.warning(f"✅ Rate limit applied to {ip}")
            
            self.event_bus.publish(
                'rate_limit_applied',
                {'ip': ip, 'rate': rate, 'burst': burst},
                EventPriority.NORMAL,
                'RateLimiter'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply rate limit to {ip}: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            return False
    
    def remove_rate_limit(self, ip: str) -> bool:
        """
        Remove rate limiting from an IP.
        
        Args:
            ip: IP to remove limit from
            
        Returns:
            True if successful
        """
        if ip not in self.active_limits:
            return True
        
        logger.info(f"Removing rate limit from {ip}")
        
        try:
            # Remove accept rule
            self._run_iptables([
                '-D', 'LONEWARRIOR_RATELIMIT',
                '-s', ip,
                '-p', 'tcp',
                '-m', 'limit', '--limit', f'{self.active_limits[ip]["rate"]}/minute',
                '--limit-burst', str(self.active_limits[ip]["burst"]),
                '-j', 'ACCEPT'
            ])
            
            # Remove drop rule
            self._run_iptables([
                '-D', 'LONEWARRIOR_RATELIMIT',
                '-s', ip,
                '-j', 'DROP'
            ])
            
            del self.active_limits[ip]
            
            logger.info(f"✅ Rate limit removed from {ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove rate limit from {ip}: {e}")
            return False
    
    def apply_port_rate_limit(self, port: int, rate: int = None, 
                             protocol: str = 'tcp') -> bool:
        """
        Apply rate limiting to a specific port.
        
        Args:
            port: Port number to limit
            rate: Connections per minute
            protocol: tcp or udp
            
        Returns:
            True if successful
        """
        rate = rate or self.default_rate
        
        logger.warning(f"⏱️ Rate limiting port {port}/{protocol}: {rate}/min")
        
        try:
            self._run_iptables([
                '-A', 'LONEWARRIOR_RATELIMIT',
                '-p', protocol,
                '--dport', str(port),
                '-m', 'state', '--state', 'NEW',
                '-m', 'limit', '--limit', f'{rate}/minute',
                '--limit-burst', str(self.default_burst),
                '-j', 'ACCEPT'
            ])
            
            # Drop excess
            self._run_iptables([
                '-A', 'LONEWARRIOR_RATELIMIT',
                '-p', protocol,
                '--dport', str(port),
                '-m', 'state', '--state', 'NEW',
                '-j', 'DROP'
            ])
            
            # Track port limit
            port_key = f"{port}/{protocol}"
            self.active_port_limits[port_key] = {
                'rate': rate,
                'protocol': protocol,
                'applied_at': datetime.now(timezone.utc)
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to rate limit port {port}: {e}")
            return False
    
    def check_expired_limits(self):
        """Check and remove expired rate limits"""
        now = datetime.now(timezone.utc).timestamp()
        expired = []
        
        for ip, limit_info in self.active_limits.items():
            if limit_info['expires_at'] < now:
                expired.append(ip)
        
        for ip in expired:
            self.remove_rate_limit(ip)
            logger.info(f"Rate limit expired for {ip}")
    
    def _init_rate_limit_chain(self):
        """Initialize rate limit iptables chain"""
        try:
            # Create chain if not exists
            self._run_iptables(['-N', 'LONEWARRIOR_RATELIMIT'])
        except Exception:
            # Chain might already exist
            pass
        
        # Ensure chain is in INPUT
        try:
            self._run_iptables(['-C', 'INPUT', '-j', 'LONEWARRIOR_RATELIMIT'])
        except Exception:
            self._run_iptables(['-I', 'INPUT', '1', '-j', 'LONEWARRIOR_RATELIMIT'])
    
    def _cleanup_all_limits(self):
        """Remove all rate limits"""
        for ip in list(self.active_limits.keys()):
            self.remove_rate_limit(ip)
        
        # Clear port limits tracking
        self.active_port_limits.clear()
        
        # Flush and delete our chain
        try:
            self._run_iptables(['-D', 'INPUT', '-j', 'LONEWARRIOR_RATELIMIT'])
            self._run_iptables(['-F', 'LONEWARRIOR_RATELIMIT'])
            self._run_iptables(['-X', 'LONEWARRIOR_RATELIMIT'])
        except Exception:
            pass
    
    def _run_iptables(self, args: List[str]) -> bool:
        """Run iptables command"""
        cmd = ['iptables'] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise Exception(result.stderr)
            return True
        except Exception as e:
            logger.error(f"iptables error: {e}")
            raise
    
    def get_active_limits(self) -> Dict[str, Any]:
        """Get all active rate limits"""
        return {
            ip: {
                'rate': info['rate'],
                'burst': info['burst'],
                'applied_at': info['applied_at'].isoformat(),
                'expires_in': max(0, info['expires_at'] - datetime.now(timezone.utc).timestamp())
            }
            for ip, info in self.active_limits.items()
        }
