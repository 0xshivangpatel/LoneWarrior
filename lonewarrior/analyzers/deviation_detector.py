"""
Deviation Detector - Detects deviations from learned baselines
"""

import logging
from typing import Dict, Any

from lonewarrior.core.event_bus import EventBus, InternalEvent, EventPriority
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Detection, DetectionType, EventType, BaselinePhase
from lonewarrior.core.state_manager import StateManager


logger = logging.getLogger(__name__)


class DeviationDetector:
    """Detects deviations from baseline"""
    
    # ONLY kernel threads that cannot be abused by attackers
    # These are kernel-managed processes that always exist and cannot execute user code
    # User-space tools (bash, sudo, etc.) are NOT whitelisted - they go through baseline learning
    KERNEL_THREAD_PREFIXES = {
        'kworker/',      # Kernel worker threads
        'ksoftirqd/',    # Soft IRQ handlers
        'kswapd',        # Swap handler
        'migration/',    # CPU migration threads
        'watchdog/',     # Hardware watchdog
        'cpuhp/',        # CPU hotplug
        'idle_inject/',  # Idle injection
        'irq/',          # IRQ handlers
        'rcu_',          # Read-Copy-Update
        'kthreadd',      # Kernel thread daemon
        'khungtaskd',    # Hung task detector
        'oom_reaper',    # OOM killer cleanup
        'writeback',     # Writeback threads
        'kcompactd',     # Memory compaction
        'kblockd',       # Block layer
        'kintegrityd',   # Block integrity
        'kdevtmpfs',     # Device tmpfs
        'netns',         # Network namespace
        'kauditd',       # Audit daemon thread
        'crypto',        # Crypto helpers
        'zswap',         # Compressed swap
        'mm_percpu_wq',  # Per-CPU workqueue
        'inet_frag_wq',  # IP fragmentation
        'kstrp',         # Kernel strparser
    }

    # Legitimate system processes that commonly appear and are generally safe
    # These are user-space but part of standard system operation
    LEGITIMATE_SYSTEM_PROCESSES = {
        'nm-dispatcher',           # NetworkManager dispatcher
        'xfconfd',                # XFCE configuration daemon
        'xfce4-mime-helper',      # XFCE MIME helper
        'xfce4-screensaver-dialog',# XFCE screensaver dialog
        'systemd-udevd',          # Device manager
        'dbus-daemon',            # D-Bus daemon
        'gdm',                    # Gnome Display Manager
        'lightdm',                # Light Display Manager
        'packagekit',             # Package manager helper
        'apt.systemd.daily',      # Daily apt maintenance
        'systemd-journald',       # Journal daemon
        'systemd-logind',        # Login manager
    }
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        # Subscribe to events
        self.event_bus.subscribe(EventType.PROCESS_NEW.value, self.handle_process_event)
        self.event_bus.subscribe(EventType.NETWORK_CONNECTION.value, self.handle_network_event)
    
    def start(self):
        """Start detector"""
        logger.info("Deviation detector started")
    
    def stop(self):
        """Stop detector"""
        logger.info("Deviation detector stopped")
    
    def _is_kernel_thread(self, process_name: str) -> bool:
        """
        Check if a process is a kernel thread.

        Kernel threads are managed by the kernel and cannot execute user code,
        so they are safe to skip. User-space processes go through baseline learning.

        Args:
            process_name: Name of the process

        Returns:
            True if process is a kernel thread
        """
        if not process_name:
            return False

        # Check prefix match (kernel threads have predictable naming)
        for pattern in self.KERNEL_THREAD_PREFIXES:
            if process_name.startswith(pattern.rstrip('/')):
                return True

        return False
    
    def handle_process_event(self, event: InternalEvent):
        """Check if process deviates from baseline"""
        # Only detect deviations after Phase 1
        if self.state.get_current_phase().value < BaselinePhase.PHASE_1_FAST.value:
            return

        data = event.data
        process_name = data.get('name') or ''
        username = data.get('username')

        # Skip kernel threads (cannot be abused, kernel-managed)
        if self._is_kernel_thread(process_name):
            return

        # Skip known legitimate system processes
        if process_name in self.LEGITIMATE_SYSTEM_PROCESSES:
            logger.debug(f"Skipping legitimate system process: {process_name}")
            return

        key = f"{process_name}:{username}"
        baseline = self.db.get_baseline('process', key)

        # Check lineage risk
        lineage_risk = data.get('lineage_risk', 0)
        base_confidence = 30.0

        if not baseline:
            # New process not in baseline
            # Boost confidence if lineage risk is high
            confidence_score = base_confidence + (lineage_risk * 3)
            description = f"Unknown process: {process_name} by {username}"
            if lineage_risk > 0:
                description += f" (lineage_risk: {lineage_risk})"
            self._create_detection(
                DetectionType.BASELINE_DEVIATION.value,
                description,
                confidence_score=confidence_score,
                data=data
            )
    
    def handle_network_event(self, event: InternalEvent):
        """Check if network connection deviates from baseline"""
        # Only detect after Phase 1
        if self.state.get_current_phase().value < BaselinePhase.PHASE_1_FAST.value:
            return
        
        data = event.data
        remote_addr = data.get('remote_addr')
        remote_port = data.get('remote_port')
        
        key = f"{remote_addr}:{remote_port}"
        baseline = self.db.get_baseline('network_dest', key)
        
        if not baseline:
            # New destination
            self._create_detection(
                DetectionType.NETWORK_ANOMALY.value,
                f"Unknown destination: {remote_addr}:{remote_port}",
                confidence_score=35.0,
                data=data
            )
    
    def _create_detection(self, detection_type: str, description: str,
                         confidence_score: float, data: Dict[str, Any]):
        """Create and publish detection"""
        detection = Detection(
            detection_type=detection_type,
            description=description,
            confidence_score=confidence_score,
            data=data
        )
        
        detection.id = self.db.insert_detection(detection)
        
        logger.info(f"Deviation detected: {description} (confidence: {confidence_score})")
        
        self.event_bus.publish(
            'detection_created',
            {
                'detection_id': detection.id,
                'type': detection_type,
                'description': description,
                'confidence': confidence_score,
            },
            EventPriority.NORMAL,
            'DeviationDetector'
        )
