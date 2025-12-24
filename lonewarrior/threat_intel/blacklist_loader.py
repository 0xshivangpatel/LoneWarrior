"""
Threat Intel Blacklist Loader - Load and manage IP blacklists
"""

import logging
import os
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from datetime import datetime, timezone

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import ThreatIntel
from lonewarrior.core.event_bus import EventBus, EventPriority


logger = logging.getLogger(__name__)


class BlacklistLoader:
    """
    Loads and manages IP blacklists for threat intelligence.
    
    Sources:
    - Built-in blacklist file
    - External threat feeds (optional)
    - Dynamic reputation system
    """
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        
        # Blacklist settings
        self.blacklist_path = config.get('threat_intel', {}).get(
            'blacklist_path', 
            '/opt/LoneWarrior/lonewarrior/threat_intel/blacklist_ips.txt'
        )
        self.external_feeds = config.get('threat_intel', {}).get('external_feeds', [])
        self.auto_block = config.get('threat_intel', {}).get('auto_block_blacklisted', True)
        
        # In-memory blacklist
        self.blacklist: Set[str] = set()
    
    def start(self):
        """Start blacklist loader and load initial blacklist"""
        self.load_blacklist()
        logger.info(f"Blacklist loader started ({len(self.blacklist)} IPs)")
    
    def stop(self):
        """Stop blacklist loader"""
        logger.info("Blacklist loader stopped")
    
    def load_blacklist(self) -> int:
        """
        Load blacklist from file and external feeds.
        
        Returns:
            Number of IPs loaded
        """
        self.blacklist.clear()
        
        # Load from file
        count = self._load_from_file()
        
        # Load from database
        count += self._load_from_database()
        
        logger.info(f"Loaded {len(self.blacklist)} blacklisted IPs")
        
        return len(self.blacklist)
    
    def _load_from_file(self) -> int:
        """Load IPs from blacklist file"""
        count = 0
        
        try:
            blacklist_file = Path(self.blacklist_path)
            
            if blacklist_file.exists():
                with open(blacklist_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Handle IP or CIDR
                            ip = line.split()[0] if ' ' in line else line
                            self.blacklist.add(ip)
                            count += 1
            else:
                logger.warning(f"Blacklist file not found: {self.blacklist_path}")
                
        except Exception as e:
            logger.error(f"Error loading blacklist file: {e}")
        
        return count
    
    def _load_from_database(self) -> int:
        """Load blacklisted IPs from database"""
        count = 0
        
        try:
            # Query for blacklisted IPs
            threats = self.db.get_blacklisted_ips()
            
            for threat in threats:
                self.blacklist.add(threat.ip_address)
                count += 1
                
        except Exception as e:
            logger.error(f"Error loading blacklist from database: {e}")
        
        return count
    
    def is_blacklisted(self, ip: str) -> bool:
        """
        Check if an IP is blacklisted.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if blacklisted
        """
        if ip in self.blacklist:
            return True
        
        # Also check database for recent additions
        threat = self.db.get_threat_intel(ip)
        if threat and threat.is_blacklisted:
            self.blacklist.add(ip)
            return True
        
        return False
    
    def add_to_blacklist(self, ip: str, reason: str = "Manual addition") -> bool:
        """
        Add an IP to the blacklist.
        
        Args:
            ip: IP to blacklist
            reason: Reason for blacklisting
            
        Returns:
            True if added
        """
        logger.warning(f"Adding {ip} to blacklist: {reason}")
        
        # Add to memory
        self.blacklist.add(ip)
        
        # Add to database
        threat = ThreatIntel(
            ip_address=ip,
            is_blacklisted=True,
            reputation_score=100,
            notes=reason
        )
        self.db.upsert_threat_intel(threat)
        
        # Trigger block if auto-block enabled
        if self.auto_block:
            self.event_bus.publish(
                'trigger_action',
                {
                    'action_type': 'ip_block',
                    'ip': ip,
                    'reason': f'Blacklisted: {reason}'
                },
                EventPriority.HIGH,
                'BlacklistLoader'
            )
        
        return True
    
    def remove_from_blacklist(self, ip: str) -> bool:
        """
        Remove an IP from the blacklist.
        
        Args:
            ip: IP to remove
            
        Returns:
            True if removed
        """
        if ip in self.blacklist:
            self.blacklist.remove(ip)
        
        # Update database
        threat = self.db.get_threat_intel(ip)
        if threat:
            threat.is_blacklisted = False
            self.db.upsert_threat_intel(threat)
        
        logger.info(f"Removed {ip} from blacklist")
        return True
    
    def get_reputation(self, ip: str) -> int:
        """
        Get reputation score for an IP (0-100, higher = more malicious).
        
        Args:
            ip: IP to check
            
        Returns:
            Reputation score
        """
        # Check if blacklisted
        if ip in self.blacklist:
            return 100
        
        # Check database
        threat = self.db.get_threat_intel(ip)
        if threat:
            return threat.reputation_score
        
        return 0
    
    def update_reputation(self, ip: str, delta: int, reason: str = "") -> int:
        """
        Update reputation score for an IP.
        
        Args:
            ip: IP address
            delta: Change in reputation (positive = more malicious)
            reason: Reason for update
            
        Returns:
            New reputation score
        """
        threat = self.db.get_threat_intel(ip)
        
        if threat:
            new_score = max(0, min(100, threat.reputation_score + delta))
            threat.reputation_score = new_score
            
            if reason:
                threat.notes = f"{threat.notes}\n{datetime.now(timezone.utc).isoformat()}: {reason}"
        else:
            new_score = max(0, min(100, 50 + delta))  # Start at 50
            threat = ThreatIntel(
                ip_address=ip,
                reputation_score=new_score,
                notes=reason
            )
        
        self.db.upsert_threat_intel(threat)
        
        # Auto-blacklist if reputation is critical
        if new_score >= 90:
            self.add_to_blacklist(ip, f"Reputation exceeded threshold: {new_score}")
        
        return new_score
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get blacklist statistics"""
        return {
            'total_blacklisted': len(self.blacklist),
            'from_file': self._count_file_entries(),
            'from_database': self._count_db_entries(),
            'auto_block_enabled': self.auto_block
        }
    
    def _count_file_entries(self) -> int:
        """Count entries in blacklist file"""
        try:
            path = Path(self.blacklist_path)
            if path.exists():
                with open(path) as f:
                    return sum(1 for line in f if line.strip() and not line.startswith('#'))
        except Exception:
            pass
        return 0
    
    def _count_db_entries(self) -> int:
        """Count blacklisted entries in database"""
        try:
            return len(self.db.get_blacklisted_ips())
        except Exception:
            return 0
    
    def export_blacklist(self, path: str) -> bool:
        """
        Export current blacklist to file.
        
        Args:
            path: Output file path
            
        Returns:
            True if successful
        """
        try:
            with open(path, 'w') as f:
                f.write(f"# LoneWarrior Blacklist Export\n")
                f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"# Total IPs: {len(self.blacklist)}\n\n")
                
                for ip in sorted(self.blacklist):
                    f.write(f"{ip}\n")
            
            logger.info(f"Exported {len(self.blacklist)} IPs to {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export blacklist: {e}")
            return False
