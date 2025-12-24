"""
Main Security Engine - Orchestrates all subsystems
"""

import logging
import time
import threading
import os
import socket
from pathlib import Path
from typing import Dict, Any, List

from lonewarrior.storage.database import Database
from lonewarrior.core.state_manager import StateManager
from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.core.health_checker import HealthChecker


logger = logging.getLogger(__name__)


def sd_notify(message: str) -> bool:
    """
    Send notification to systemd.
    
    Args:
        message: Notification message (e.g., 'READY=1', 'WATCHDOG=1')
        
    Returns:
        True if notification was sent successfully
    """
    notify_socket = os.environ.get('NOTIFY_SOCKET')
    if not notify_socket:
        return False  # Not running under systemd
    
    try:
        if notify_socket.startswith('@'):
            # Abstract socket
            notify_socket = '\0' + notify_socket[1:]
        
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(notify_socket)
        sock.sendall(message.encode())
        sock.close()
        return True
    except Exception as e:
        logger.debug(f"sd_notify failed: {e}")
        return False


class SecurityEngine:
    """
    Main orchestration engine for LoneWarrior
    Coordinates collectors, analyzers, and responders
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize security engine
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.running = False
        
        # Initialize core components
        db_path = Path(config['general']['data_dir']) / 'lonewarrior.db'
        self.db = Database(str(db_path))
        
        self.state_manager = StateManager(self.db, config)
        self.event_bus = EventBus()
        self.health_checker = HealthChecker(config)
        
        # Component lists
        self.collectors = []
        self.analyzers = []
        self.responders = []
        
        # Initialize components
        self._init_collectors()
        self._init_analyzers()
        self._init_responders()
        
        # Maintenance thread
        self.maintenance_thread = None
        
        logger.info("Security Engine initialized")
    
    def _init_collectors(self):
        """Initialize data collectors"""
        from lonewarrior.collectors.process_collector import ProcessCollector
        from lonewarrior.collectors.network_collector import NetworkCollector
        from lonewarrior.collectors.auth_collector import AuthCollector
        from lonewarrior.collectors.file_collector import FileCollector
        
        logger.info("Initializing collectors...")
        
        # Process collector
        self.collectors.append(ProcessCollector(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        ))
        
        # Network collector
        self.collectors.append(NetworkCollector(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        ))
        
        # Auth collector
        self.collectors.append(AuthCollector(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        ))
        
        # File integrity collector
        if self.config.get('file_integrity', {}).get('enabled', False):
            self.collectors.append(FileCollector(
                self.config,
                self.db,
                self.event_bus,
                self.state_manager
            ))
        
        logger.info(f"Initialized {len(self.collectors)} collectors")
    
    def _init_analyzers(self):
        """Initialize threat analyzers"""
        from lonewarrior.analyzers.baseline_learner import BaselineLearner
        from lonewarrior.analyzers.invariant_detector import InvariantDetector
        from lonewarrior.analyzers.deviation_detector import DeviationDetector
        from lonewarrior.analyzers.confidence_scorer import ConfidenceScorer
        from lonewarrior.analyzers.threat_intel_analyzer import ThreatIntelAnalyzer

        logger.info("Initializing analyzers...")

        # Baseline learner
        baseline_learner = BaselineLearner(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        )
        self.analyzers.append(baseline_learner)

        # Invariant detector
        invariant_detector = InvariantDetector(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        )
        self.analyzers.append(invariant_detector)

        # Deviation detector
        deviation_detector = DeviationDetector(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        )
        self.analyzers.append(deviation_detector)

        #  Confidence scorer (listens to all detections)
        confidence_scorer = ConfidenceScorer(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        )
        self.analyzers.append(confidence_scorer)

        # Threat intel analyzer (auth failures -> detection)
        threat_intel_analyzer = ThreatIntelAnalyzer(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        )
        self.analyzers.append(threat_intel_analyzer)

        # Kill-chain tracker
        from lonewarrior.analyzers.killchain_tracker import KillChainTracker
        killchain_tracker = KillChainTracker(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        )
        self.analyzers.append(killchain_tracker)

        # Baseline versioning
        from lonewarrior.analyzers.baseline_versioning import BaselineVersionManager
        baseline_version_manager = BaselineVersionManager(
            self.config,
            self.db,
            self.event_bus
        )
        self.analyzers.append(baseline_version_manager)

        # Correlation analyzer (correlates multiple detections)
        from lonewarrior.analyzers.correlation_analyzer import CorrelationAnalyzer
        correlation_analyzer = CorrelationAnalyzer(
            self.config,
            self.db,
            self.event_bus,
            self.state_manager
        )
        self.analyzers.append(correlation_analyzer)

        # External threat intel (AbuseIPDB, Project Honey Pot)
        if self.config.get('threat_intel', {}).get('external_feeds', {}).get('enabled', False):
            from lonewarrior.analyzers.external_threat_intel import ExternalThreatIntel
            external_threat_intel = ExternalThreatIntel(self.config, self.db, self.event_bus)
            external_threat_intel.start()
            self.analyzers.append(external_threat_intel)

        logger.info(f"Initialized {len(self.analyzers)} analyzers")
    
    def _init_responders(self):
        """Initialize autonomous responders"""
        from lonewarrior.responders.action_executor import ActionExecutor
        from lonewarrior.responders.containment_mode import ContainmentMode
        from lonewarrior.responders.process_responder import ProcessResponder
        from lonewarrior.core.rollback_manager import RollbackManager
        
        logger.info("Initializing responders...")
        
        if self.config['actions']['enabled']:
            # Action executor (IP blocking, etc.)
            action_executor = ActionExecutor(
                self.config,
                self.db,
                self.event_bus,
                self.state_manager
            )
            self.responders.append(action_executor)
            
            # Containment mode handler
            containment_mode = ContainmentMode(
                self.config,
                self.db,
                self.event_bus,
                self.state_manager
            )
            self.responders.append(containment_mode)
            
            # Process responder
            process_responder = ProcessResponder(
                self.config,
                self.db,
                self.event_bus,
                self.state_manager
            )
            self.responders.append(process_responder)
            
            # Rollback manager
            rollback_manager = RollbackManager(
                self.config,
                self.db,
                self.event_bus
            )
            self.responders.append(rollback_manager)
            
            # User responder
            from lonewarrior.responders.user_responder import UserResponder
            user_responder = UserResponder(
                self.config,
                self.db,
                self.event_bus,
                self.state_manager
            )
            self.responders.append(user_responder)
            
            # Container responder
            from lonewarrior.responders.container_responder import ContainerResponder
            container_responder = ContainerResponder(
                self.config,
                self.db,
                self.event_bus,
                self.state_manager
            )
            self.responders.append(container_responder)
            
            # Rate limiter
            from lonewarrior.responders.rate_limiter import RateLimiter
            rate_limiter = RateLimiter(
                self.config,
                self.db,
                self.event_bus,
                self.state_manager
            )
            self.responders.append(rate_limiter)
            
            # Blacklist loader
            from lonewarrior.threat_intel.blacklist_loader import BlacklistLoader
            blacklist_loader = BlacklistLoader(
                self.config,
                self.db,
                self.event_bus
            )
            self.responders.append(blacklist_loader)
        
        logger.info(f"Initialized {len(self.responders)} responders")
    
    def start(self):
        """Start the security engine"""
        if self.running:
            logger.warning("Engine already running")
            return
        
        logger.info("=" * 60)
        logger.info("Starting LoneWarrior Security Engine")
        logger.info("=" * 60)
        
        self.running = True
        
        # Start event bus
        self.event_bus.start()
        
        # Start collectors
        for collector in self.collectors:
            collector.start()
            logger.info(f"Started {collector.__class__.__name__}")
        
        # Start analyzers
        for analyzer in self.analyzers:
            analyzer.start()
            logger.info(f"Started {analyzer.__class__.__name__}")
        
        # Start responders
        for responder in self.responders:
            responder.start()
            logger.info(f"Started {responder.__class__.__name__}")
        
        # Start maintenance thread
        self.maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=False)
        self.maintenance_thread.start()
        
        logger.info("=" * 60)
        logger.info(f"Engine started in Phase {self.state_manager.get_current_phase().name}")
        logger.info("=" * 60)
        
        # Notify systemd that we're ready
        if sd_notify('READY=1'):
            logger.debug("Notified systemd: READY=1")
        
        # Main loop
        try:
            while self.running:
                # Send watchdog heartbeat to systemd
                sd_notify('WATCHDOG=1')
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the security engine"""
        if not self.running:
            return
        
        logger.info("=" * 60)
        logger.info("Stopping LoneWarrior Security Engine")
        logger.info("=" * 60)
        
        self.running = False
        
        # Stop responders first
        for responder in self.responders:
            responder.stop()
            logger.info(f"Stopped {responder.__class__.__name__}")
        
        # Stop analyzers
        for analyzer in self.analyzers:
            analyzer.stop()
            logger.info(f"Stopped {analyzer.__class__.__name__}")
        
        # Stop collectors
        for collector in self.collectors:
            collector.stop()
            logger.info(f"Stopped {collector.__class__.__name__}")
        
        # Stop event bus
        self.event_bus.stop()
        
        # Wait for maintenance thread
        if self.maintenance_thread and self.maintenance_thread.is_alive():
            self.maintenance_thread.join(timeout=5.0)
        
        logger.info("=" * 60)
        logger.info("Engine stopped cleanly")
        logger.info("=" * 60)
    
    def _maintenance_loop(self):
        """Periodic maintenance tasks"""
        logger.info("Maintenance loop started")
        
        last_phase_check = time.time()
        last_confidence_decay = time.time()
        last_health_check = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check for phase transitions every 60 seconds
                if current_time - last_phase_check >= 60:
                    if self.state_manager.check_phase_transition():
                        phase = self.state_manager.get_current_phase()
                        logger.info(f"🎯 Phase transition: now in {phase.name}")
                        
                        # Publish phase change event
                        self.event_bus.publish(
                            'phase_changed',
                            {'phase': phase.value, 'phase_name': phase.name},
                            EventPriority.HIGH,
                            'engine'
                        )
                    last_phase_check = current_time
                
                # Decay attack confidence every 5 minutes
                if current_time - last_confidence_decay >= 300:
                    self.state_manager.decay_attack_confidence(decay_amount=5.0)
                    last_confidence_decay = current_time
                
                # Health checks every 30 seconds
                if current_time - last_health_check >= 30:
                    if not self.health_checker.check_system_health():
                        logger.warning("System health check failed!")
                    last_health_check = current_time
                
                time.sleep(10)
                
            except KeyboardInterrupt:
                logger.info("Maintenance loop interrupted")
                break
            except Exception as e:
                logger.error(f"Error in maintenance loop: {e}", exc_info=True)
                time.sleep(10)
        
        logger.info("Maintenance loop terminated")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current engine status"""
        state = self.state_manager.get_state_summary()
        
        return {
            'running': self.running,
            'state': state,
            'collectors': len(self.collectors),
            'analyzers': len(self.analyzers),
            'responders': len(self.responders),
            'event_queue_size': self.event_bus.get_queue_size(),
        }
