"""
Health Checker - System health monitoring
"""

import logging
import subprocess
import socket
from typing import Dict, Any, List


logger = logging.getLogger(__name__)


class HealthChecker:
    """Monitors system health and critical services"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize health checker
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.critical_services = config['health']['critical_services']
        self.network_check_host = config['health']['network_check_host']
    
    def check_system_health(self) -> bool:
        """
        Perform complete system health check
        
        Returns:
            True if all checks pass
        """
        checks = [
            self.check_critical_services(),
            self.check_network_connectivity(),
        ]
        
        return all(checks)
    
    def check_critical_services(self) -> bool:
        """
        Check if critical services are running.
        Only checks services that actually exist on the system.
        
        Returns:
            True if all available critical services are running
        """
        all_ok = True
        
        for service in self.critical_services:
            # First check if the service exists on this system
            if not self._service_exists(service):
                logger.debug(f"Service {service} not installed, skipping health check")
                continue
            
            if not self._is_service_running(service):
                logger.error(f"Critical service {service} is not running!")
                all_ok = False
        
        return all_ok
    
    def _service_exists(self, service_name: str) -> bool:
        """
        Check if a systemd service unit exists on this system.
        
        Args:
            service_name: Name of service
            
        Returns:
            True if service unit file exists
        """
        try:
            # Check if the service unit is known to systemd
            result = subprocess.run(
                ['systemctl', 'list-unit-files', f'{service_name}.service'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # If the service exists, it will appear in the output
            return service_name in result.stdout
        except Exception:
            # Can't determine, assume it exists to be safe
            return True
    
    def _is_service_running(self, service_name: str) -> bool:
        """
        Check if a systemd service is running
        
        Args:
            service_name: Name of service
            
        Returns:
            True if service is active
        """
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() == 'active'
        except Exception as e:
            logger.error(f"Error checking service {service_name}: {e}")
            return False
    
    def check_network_connectivity(self) -> bool:
        """
        Check basic network connectivity
        
        Returns:
            True if network is reachable
        """
        try:
            # Try to create a socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.network_check_host, 53))  # DNS port
            sock.close()
            return True
        except Exception as e:
            logger.warning(f"Network connectivity check failed: {e}")
            return False
