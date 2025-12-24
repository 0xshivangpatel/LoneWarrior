"""
Process Responder - Process termination and management
"""

import os
import signal
import logging
import subprocess
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone, timedelta

from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Action, ActionType, ActionStatus
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class ProcessResponder:
    """
    Handles process termination and management.
    
    Features:
    - Graceful termination (SIGTERM → SIGKILL escalation)
    - Process tree killing (kill parent and all children)
    - Monitoring for process respawn
    """
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Settings
        self.escalation_delay = config.get('actions', {}).get('process_kill', {}).get('escalation_delay', 5)
        self.kill_children = config.get('actions', {}).get('process_kill', {}).get('kill_children', True)
        
        # Track killed processes for respawn detection
        self.killed_processes: Dict[str, datetime] = {}
        
        # Max age for killed_processes entries (for cleanup)
        self._killed_processes_max_age = timedelta(seconds=300)
        
        # Subscribe to events
        self._event_handlers = [
            ('kill_process', self.handle_kill_request),
            ('process_new', self.check_respawn)
        ]
        for event_type, handler in self._event_handlers:
            self.event_bus.subscribe(event_type, handler)
    
    def start(self):
        """Start process responder"""
        logger.info("Process responder started")
    
    def stop(self):
        """Stop process responder"""
        # Unsubscribe from events
        for event_type, handler in self._event_handlers:
            try:
                self.event_bus.unsubscribe(event_type, handler)
            except Exception:
                pass
        
        logger.info("Process responder stopped")
    
    def handle_kill_request(self, event):
        """Handle process kill request"""
        data = event.data
        pid = data.get('pid')
        process_name = data.get('name', 'unknown')
        detection_id = data.get('detection_id')
        kill_tree = data.get('kill_tree', self.kill_children)
        
        if pid:
            self.kill_process(pid, process_name, detection_id, kill_tree)
    
    def kill_process(self, pid: int, process_name: str = "unknown",
                    detection_id: Optional[int] = None,
                    kill_tree: bool = True) -> bool:
        """
        Kill a process with graceful escalation.
        
        Args:
            pid: Process ID to kill
            process_name: Name for logging
            detection_id: Associated detection
            kill_tree: Whether to kill child processes too
            
        Returns:
            True if process was killed
        """
        logger.warning(f"🔪 Killing process: {process_name} (PID {pid})")
        
        # Record action
        action = Action(
            action_type=ActionType.PROCESS_KILL.value,
            status=ActionStatus.EXECUTING.value,
            detection_id=detection_id,
            target=str(pid),
            parameters={
                'name': process_name,
                'kill_tree': kill_tree,
                'escalation_delay': self.escalation_delay
            }
        )
        action_id = self.db.insert_action(action)
        
        try:
            pids_to_kill = [pid]
            
            # Get child processes if killing tree
            if kill_tree:
                children = self._get_child_pids(pid)
                pids_to_kill.extend(children)
                if children:
                    logger.info(f"Including {len(children)} child processes")
            
            # Kill in reverse order (children first)
            killed_count = 0
            for target_pid in reversed(pids_to_kill):
                if self._kill_single_process(target_pid):
                    killed_count += 1
            
            # Track for respawn detection
            self.killed_processes[process_name] = datetime.now(timezone.utc)
            
            # Update action
            self.db.update_action(
                action_id, 
                ActionStatus.SUCCESS.value,
                result=f"Killed {killed_count}/{len(pids_to_kill)} processes"
            )
            
            logger.warning(f"✅ Killed {killed_count} processes (PID {pid} tree)")
            
            # Publish event
            self.event_bus.publish(
                'process_killed',
                {'pid': pid, 'name': process_name, 'count': killed_count},
                EventPriority.HIGH,
                'ProcessResponder'
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to kill process {pid}: {e}")
            self.db.update_action(action_id, ActionStatus.FAILED.value, error=str(e))
            return False
    
    def _kill_single_process(self, pid: int) -> bool:
        """
        Kill a single process with SIGTERM → SIGKILL escalation.
        
        Args:
            pid: Process ID
            
        Returns:
            True if process was killed or didn't exist
        """
        try:
            # Check if process exists
            os.kill(pid, 0)
        except OSError:
            logger.debug(f"Process {pid} already dead")
            return True
        
        try:
            # First try SIGTERM (graceful)
            logger.debug(f"Sending SIGTERM to {pid}")
            os.kill(pid, signal.SIGTERM)
            
            # Wait for process to die
            for _ in range(self.escalation_delay):
                time.sleep(1)
                try:
                    os.kill(pid, 0)
                except OSError:
                    logger.debug(f"Process {pid} terminated gracefully")
                    return True
            
            # Process still alive, escalate to SIGKILL
            logger.warning(f"Process {pid} didn't respond to SIGTERM, sending SIGKILL")
            os.kill(pid, signal.SIGKILL)
            
            # Verify it's dead
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
                logger.error(f"Process {pid} survived SIGKILL!")
                return False
            except OSError:
                logger.debug(f"Process {pid} killed with SIGKILL")
                return True
                
        except PermissionError:
            logger.error(f"Permission denied killing process {pid}")
            return False
        except Exception as e:
            logger.error(f"Error killing process {pid}: {e}")
            return False
    
    def _get_child_pids(self, parent_pid: int) -> List[int]:
        """
        Get all child process PIDs recursively.
        
        Args:
            parent_pid: Parent process ID
            
        Returns:
            List of child PIDs
        """
        children = []
        try:
            # Use pgrep to find children
            result = subprocess.run(
                ['pgrep', '-P', str(parent_pid)],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        child_pid = int(line)
                        children.append(child_pid)
                        # Recursively get grandchildren
                        children.extend(self._get_child_pids(child_pid))
        except Exception as e:
            logger.error(f"Error getting children of {parent_pid}: {e}")
        
        return children
    
    def check_respawn(self, event):
        """Check if a killed process has respawned"""
        data = event.data
        process_name = data.get('name')
        
        if process_name in self.killed_processes:
            kill_time = self.killed_processes[process_name]
            elapsed = (datetime.now(timezone.utc) - kill_time).total_seconds()
            
            # If respawned within 60 seconds, it's suspicious
            if elapsed < 60:
                logger.warning(f"⚠️ Process {process_name} respawned after {elapsed:.1f}s!")
                
                # Publish respawn detection
                self.event_bus.publish(
                    'process_respawn_detected',
                    {
                        'name': process_name,
                        'pid': data.get('pid'),
                        'elapsed_seconds': elapsed
                    },
                    EventPriority.HIGH,
                    'ProcessResponder'
                )
            else:
                # Clean up old entry
                del self.killed_processes[process_name]
        
        # Periodic cleanup of old entries
        self._cleanup_killed_processes()
    
    def _cleanup_killed_processes(self):
        """Remove old entries from killed_processes dictionary"""
        now = datetime.now(timezone.utc)
        expired = [
            name for name, kill_time in self.killed_processes.items()
            if (now - kill_time) > self._killed_processes_max_age
        ]
        for name in expired:
            del self.killed_processes[name]
    
    def kill_by_name(self, process_name: str, detection_id: Optional[int] = None) -> int:
        """
        Kill all processes matching a name.
        
        Args:
            process_name: Process name to match
            detection_id: Associated detection
            
        Returns:
            Number of processes killed
        """
        killed = 0
        try:
            # Find all matching PIDs
            result = subprocess.run(
                ['pgrep', '-f', process_name],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        pid = int(line)
                        # Don't kill ourselves
                        if pid != os.getpid():
                            if self.kill_process(pid, process_name, detection_id, kill_tree=True):
                                killed += 1
        except Exception as e:
            logger.error(f"Error killing processes by name '{process_name}': {e}")
        
        return killed
