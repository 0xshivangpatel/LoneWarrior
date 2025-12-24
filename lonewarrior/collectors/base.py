"""
Base Collector - Abstract base class for all data collectors
"""

import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from lonewarrior.storage.database import Database
from lonewarrior.core.event_bus import EventBus, EventPriority
from lonewarrior.core.state_manager import StateManager
from lonewarrior.utils.errors import CollectorError, ErrorSeverity, log_and_continue


logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Abstract base class for data collectors"""
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus, state_manager: StateManager):
        """
        Initialize collector
        
        Args:
            config: Configuration dictionary
            database: Database instance
            event_bus: Event bus for publishing events
            state_manager: State manager instance
        """
        self.config = config
        self.db = database
        self.event_bus = event_bus
        self.state = state_manager
        
        self.running = False
        self.thread: Optional[threading.Thread] = None
        
        # Collector-specific interval
        self.interval = self._get_collection_interval()
        
        self.logger = logging.getLogger(f"lonewarrior.collectors.{self.__class__.__name__}")
    
    @abstractmethod
    def _get_collection_interval(self) -> int:
        """
        Get collection interval in seconds
        
        Returns:
            Interval in seconds
        """
        pass
    
    @abstractmethod
    def collect(self):
        """
        Perform data collection
        Must be implemented by subclasses
        """
        pass
    
    def start(self):
        """Start collector thread"""
        if self.running:
            self.logger.warning("Collector already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._collection_loop, daemon=True)
        self.thread.start()
        self.logger.info(f"Collector started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop collector thread"""
        if not self.running:
            return
        
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=self.interval + 5)
        
        self.logger.info("Collector stopped")
    
    def _collection_loop(self):
        """Main collection loop (runs in separate thread)"""
        self.logger.info("Collection loop started")
        consecutive_errors = 0
        max_consecutive_errors = 5

        while self.running:
            try:
                self.collect()
                consecutive_errors = 0  # Reset on success
                time.sleep(self.interval)
            except Exception as e:
                consecutive_errors += 1
                # Use consistent error handling with severity based on error count
                severity = ErrorSeverity.HIGH if consecutive_errors >= 3 else ErrorSeverity.MEDIUM
                log_and_continue(
                    error=e,
                    component=self.__class__.__name__,
                    operation="data collection",
                    severity=severity
                )
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.critical(
                        f"Too many consecutive errors ({consecutive_errors}), "
                        f"collector may be in a bad state"
                    )
                time.sleep(self.interval)

        self.logger.info("Collection loop terminated")
    
    def publish_event(self, event_type: str, data: Dict[str, Any], priority: EventPriority = EventPriority.NORMAL):
        """
        Publish event to event bus
        
        Args:
            event_type: Type of event
            data: Event data
            priority: Event priority
        """
        self.event_bus.publish(
            event_type=event_type,
            data=data,
            priority=priority,
            source=self.__class__.__name__
        )
