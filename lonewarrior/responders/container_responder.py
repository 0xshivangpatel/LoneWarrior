"""
Container Responder - Docker container isolation and management
"""

import logging
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Action, ActionType, ActionStatus, Snapshot
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class ContainerResponder:
    """
    Handles Docker container isolation and management.
    
    Features:
    - Isolate containers (disconnect from networks)
    - Pause/unpause containers
    - Stop suspicious containers
    - Capture container state for forensics
    """
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Track isolated containers
        self.isolated_containers: Dict[str, Dict[str, Any]] = {}
        
        # Check Docker availability
        self.docker_available = self._check_docker()
        
        # Subscribe to events
        self._event_handlers = [
            ('isolate_container', self.handle_isolate_request),
            ('restore_container', self.handle_restore_request),
            ('stop_container', self.handle_stop_request)
        ]
        for event_type, handler in self._event_handlers:
            self.event_bus.subscribe(event_type, handler)
    
    def start(self):
        """Start container responder"""
        if self.docker_available:
            logger.info("Container responder started (Docker available)")
        else:
            logger.info("Container responder started (Docker not available)")
    
    def stop(self):
        """Stop container responder and restore containers"""
        for container_id in list(self.isolated_containers.keys()):
            self.restore_container(container_id)
        
        # Unsubscribe from events
        for event_type, handler in self._event_handlers:
            try:
                self.event_bus.unsubscribe(event_type, handler)
            except Exception:
                pass
        
        logger.info("Container responder stopped")
    
    def _check_docker(self) -> bool:
        """Check if Docker is available"""
        try:
            result = subprocess.run(
                ['docker', 'version'],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def handle_isolate_request(self, event):
        """Handle container isolation request"""
        data = event.data
        container_id = data.get('container_id')
        detection_id = data.get('detection_id')
        
        if container_id:
            self.isolate_container(container_id, detection_id)
    
    def handle_restore_request(self, event):
        """Handle container restore request"""
        data = event.data
        container_id = data.get('container_id')
        
        if container_id:
            self.restore_container(container_id)
    
    def handle_stop_request(self, event):
        """Handle container stop request"""
        data = event.data
        container_id = data.get('container_id')
        detection_id = data.get('detection_id')
        
        if container_id:
            self.stop_container(container_id, detection_id)
    
    def isolate_container(self, container_id: str, 
                         detection_id: Optional[int] = None) -> bool:
        """
        Isolate a container by disconnecting from all networks.
        
        Args:
            container_id: Container ID or name
            detection_id: Associated detection
            
        Returns:
            True if successful
        """
        if not self.docker_available:
            logger.warning("Docker not available, cannot isolate container")
            return False
        
        logger.warning(f"🔒 Isolating container: {container_id}")
        
        # Create snapshot
        snapshot = self._create_container_snapshot(container_id)
        snapshot_id = self.db.insert_snapshot(snapshot)
        
        # Record action
        action = Action(
            action_type=ActionType.CONTAINER_ISOLATE.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=detection_id,
            target=container_id,
            parameters={},
            snapshot_id=snapshot_id
        )
        action_id = self.db.insert_action(action)
        
        try:
            # Get current networks
            networks = self._get_container_networks(container_id)
            
            # Disconnect from all networks
            disconnect_failures = []
            for network in networks:
                result = subprocess.run(
                    ['docker', 'network', 'disconnect', '--force', network, container_id],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    disconnect_failures.append(f"{network}: {result.stderr}")
                    logger.error(f"Failed to disconnect {container_id} from {network}: {result.stderr}")
                else:
                    logger.info(f"Disconnected {container_id} from {network}")
            
            # Only track container if we successfully disconnected from at least some networks
            if disconnect_failures and len(disconnect_failures) == len(networks):
                raise Exception(f"Failed to disconnect from any network: {disconnect_failures}")
            
            # Track for restore (only networks we successfully disconnected from)
            # Use set difference for robust filtering instead of string matching
            failed_networks = {f.split(':')[0] for f in disconnect_failures}  # Extract network names
            disconnected_networks = [n for n in networks if n not in failed_networks]
            self.isolated_containers[container_id] = {
                'networks': disconnected_networks,
                'isolated_at': datetime.now(timezone.utc)
            }
            
            self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                 result=f"Isolated from {len(networks)} networks")
            
            logger.warning(f"✅ Container {container_id} isolated")
            
            self.event_bus.publish(
                'container_isolated',
                {'container_id': container_id, 'networks': networks},
                EventPriority.HIGH,
                'ContainerResponder'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to isolate container {container_id}: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            return False
    
    def restore_container(self, container_id: str) -> bool:
        """
        Restore a container's network connections.
        
        Args:
            container_id: Container to restore
            
        Returns:
            True if successful
        """
        if container_id not in self.isolated_containers:
            logger.warning(f"Container {container_id} not in isolation tracking")
            return False
        
        logger.info(f"🔓 Restoring container: {container_id}")
        
        action = Action(
            action_type=ActionType.CONTAINER_RESTORE.value,
            status=ActionStatus.EXECUTING.value,
            target=container_id,
            parameters={}
        )
        action_id = self.db.insert_action(action)
        
        try:
            networks = self.isolated_containers[container_id]['networks']
            
            reconnect_failures = []
            for network in networks:
                result = subprocess.run(
                    ['docker', 'network', 'connect', network, container_id],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    reconnect_failures.append(f"{network}: {result.stderr}")
                    logger.error(f"Failed to reconnect {container_id} to {network}: {result.stderr}")
                else:
                    logger.info(f"Reconnected {container_id} to {network}")
            
            if reconnect_failures:
                logger.warning(f"Some network reconnections failed for {container_id}: {reconnect_failures}")
            
            # Only remove from tracking if ALL reconnections succeeded
            # to allow retry of failed reconnections
            if not reconnect_failures:
                del self.isolated_containers[container_id]
                self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                     result=f"Restored to {len(networks)} networks")
            else:
                # Update tracking to only include networks we failed to reconnect
                failed_networks = {f.split(':')[0] for f in reconnect_failures}
                self.isolated_containers[container_id]['networks'] = [
                    n for n in networks if n in failed_networks
                ]
                self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                     result=f"Partially restored, {len(reconnect_failures)} failed")
            
            logger.info(f"✅ Container {container_id} restored")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore container {container_id}: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            return False
    
    def stop_container(self, container_id: str, 
                      detection_id: Optional[int] = None) -> bool:
        """
        Stop a suspicious container.
        
        Args:
            container_id: Container to stop
            detection_id: Associated detection
            
        Returns:
            True if successful
        """
        if not self.docker_available:
            return False
        
        logger.warning(f"🛑 Stopping container: {container_id}")
        
        snapshot = self._create_container_snapshot(container_id)
        snapshot_id = self.db.insert_snapshot(snapshot)
        
        action = Action(
            action_type=ActionType.CONTAINER_ISOLATE.value,  # Use ISOLATE for stop too
            status=ActionStatus.EXECUTING.value,
            detection_id=detection_id,
            target=container_id,
            parameters={'action': 'stop'},
            snapshot_id=snapshot_id
        )
        action_id = self.db.insert_action(action)
        
        try:
            result = subprocess.run(
                ['docker', 'stop', container_id],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode != 0:
                raise Exception(f"docker stop failed: {result.stderr}")
            
            self.db.update_action(action_id, ActionStatus.SUCCESS.value,
                                 result="Container stopped")
            
            logger.warning(f"✅ Container {container_id} stopped")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop container {container_id}: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            return False
    
    def pause_container(self, container_id: str) -> bool:
        """Pause a container (preserves state)"""
        if not self.docker_available:
            return False
        
        try:
            result = subprocess.run(
                ['docker', 'pause', container_id],
                capture_output=True, timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to pause container {container_id}: {e}")
            return False
    
    def unpause_container(self, container_id: str) -> bool:
        """Unpause a paused container"""
        if not self.docker_available:
            return False
        
        try:
            result = subprocess.run(
                ['docker', 'unpause', container_id],
                capture_output=True, timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to unpause container {container_id}: {e}")
            return False
    
    def _get_container_networks(self, container_id: str) -> List[str]:
        """Get list of networks a container is connected to"""
        networks = []
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format', 
                 '{{range $key, $value := .NetworkSettings.Networks}}{{$key}} {{end}}',
                 container_id],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                networks = result.stdout.strip().split()
        except Exception as e:
            logger.error(f"Error getting container networks: {e}")
        
        return networks
    
    def _create_container_snapshot(self, container_id: str) -> Snapshot:
        """Create snapshot of container state"""
        state_data = {'container_id': container_id}
        
        try:
            result = subprocess.run(
                ['docker', 'inspect', container_id],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                import json
                state_data['inspect'] = json.loads(result.stdout)
        except Exception:
            pass
        
        return Snapshot(
            snapshot_type='container_state',
            state_data=state_data
        )
    
    def get_suspicious_containers(self) -> List[Dict[str, Any]]:
        """
        Identify potentially suspicious containers.
        
        Returns:
            List of container info dictionaries
        """
        suspicious = []
        
        if not self.docker_available:
            return suspicious
        
        try:
            # Get all running containers
            result = subprocess.run(
                ['docker', 'ps', '--format', '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}'],
                capture_output=True, text=True, timeout=10
            )
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split('|')
                if len(parts) >= 4:
                    container = {
                        'id': parts[0],
                        'name': parts[1],
                        'image': parts[2],
                        'status': parts[3]
                    }
                    
                    # Check for suspicious indicators
                    if self._is_container_suspicious(container):
                        suspicious.append(container)
        
        except Exception as e:
            logger.error(f"Error checking containers: {e}")
        
        return suspicious
    
    def _is_container_suspicious(self, container: Dict[str, Any]) -> bool:
        """Check if a container shows suspicious characteristics"""
        # Check for privileged mode, host network, etc.
        # This is a simplified version
        return False
