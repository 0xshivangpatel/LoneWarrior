"""
Event Bus - Internal pub/sub for component communication
"""

import logging
import queue
import threading
from typing import Callable, Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


logger = logging.getLogger(__name__)


class EventPriority(Enum):
    """Event priority levels"""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class InternalEvent:
    """Internal event for component communication"""
    event_type: str
    priority: EventPriority
    data: Dict[str, Any]
    timestamp: datetime
    source: str
    
    def __lt__(self, other):
        """Compare by priority for priority queue"""
        return self.priority.value < other.priority.value


class EventBus:
    """
    Internal event bus for decoupled component communication
    Uses pub/sub pattern with priority queue
    """
    
    def __init__(self, max_queue_size: int = 10000):
        """
        Initialize event bus
        
        Args:
            max_queue_size: Maximum events in queue
        """
        self.subscribers: Dict[str, List[Callable]] = {}
        self.event_queue = queue.PriorityQueue(maxsize=max_queue_size)
        self.running = False
        self.dispatch_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        logger.info("Event bus initialized")
    
    def subscribe(self, event_type: str, callback: Callable):
        """
        Subscribe to event type
        
        Args:
            event_type: Type of event to subscribe to (or '*' for all)
            callback: Function to call when event is published
        """
        with self._lock:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            self.subscribers[event_type].append(callback)
            logger.debug(f"Subscribed {callback.__name__} to {event_type}")
    
    def unsubscribe(self, event_type: str, callback: Callable):
        """
        Unsubscribe from event type
        
        Args:
            event_type: Type of event
            callback: Callback function to remove
        """
        with self._lock:
            if event_type in self.subscribers:
                self.subscribers[event_type].remove(callback)
                logger.debug(f"Unsubscribed {callback.__name__} from {event_type}")
    
    def publish(self, event_type: str, data: Dict[str, Any], 
                priority: EventPriority = EventPriority.NORMAL, source: str = "unknown"):
        """
        Publish event to bus
        
        Args:
            event_type: Type of event
            data: Event data dictionary
            priority: Event priority
            source: Source component name
        """
        event = InternalEvent(
            event_type=event_type,
            priority=priority,
            data=data,
            timestamp=datetime.now(timezone.utc),
            source=source
        )
        
        try:
            # Use negative priority for max heap (higher priority first)
            self.event_queue.put((-priority.value, event), block=False)
        except queue.Full:
            logger.error(f"Event queue full! Dropping {event_type} event from {source}")
    
    def start(self):
        """Start event dispatch thread"""
        if self.running:
            logger.warning("Event bus already running")
            return
        
        self.running = True
        self.dispatch_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self.dispatch_thread.start()
        logger.info("Event bus started")
    
    def stop(self):
        """Stop event dispatch thread"""
        logger.info("Stopping event bus...")
        self.running = False
        
        if self.dispatch_thread:
            self.dispatch_thread.join(timeout=5.0)
        
        logger.info("Event bus stopped")
    
    def _dispatch_loop(self):
        """Main dispatch loop (runs in separate thread)"""
        logger.info("Event dispatch loop started")
        
        while self.running:
            try:
                # Get next event with timeout
                priority, event = self.event_queue.get(timeout=1.0)
                self._dispatch_event(event)
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error in dispatch loop: {e}", exc_info=True)
        
        logger.info("Event dispatch loop terminated")
    
    def _dispatch_event(self, event: InternalEvent):
        """
        Dispatch event to subscribers
        
        Args:
            event: Event to dispatch
        """
        subscribers = []
        
        with self._lock:
            # Get specific subscribers
            if event.event_type in self.subscribers:
                subscribers.extend(self.subscribers[event.event_type])
            
            # Get wildcard subscribers
            if '*' in self.subscribers:
                subscribers.extend(self.subscribers['*'])
        
        # Call all subscribers
        for callback in subscribers:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Error in subscriber {callback.__name__} for {event.event_type}: {e}",
                           exc_info=True)
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return self.event_queue.qsize()
    
    def clear_queue(self):
        """Clear all pending events"""
        with self.event_queue.mutex:
            self.event_queue.queue.clear()
        logger.warning("Event queue cleared")
