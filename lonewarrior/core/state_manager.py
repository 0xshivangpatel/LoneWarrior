"""
State Manager - Tracks system state and baseline phases
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from lonewarrior.storage.models import BaselinePhase
from lonewarrior.storage.database import Database


logger = logging.getLogger(__name__)


class StateManager:
    """
    Manages system state including baseline phase, freeze status, and containment
    """
    
    def __init__(self, database: Database, config: Dict[str, Any]):
        """
        Initialize state manager
        
        Args:
            database: Database instance
            config: Configuration dictionary
        """
        self.db = database
        self.config = config
        
        # Initialize state if not exists
        self._initialize_state()
    
    def _initialize_state(self):
        """Initialize default state values"""
        if not self.db.get_state('phase'):
            self.db.set_state('phase', str(BaselinePhase.PHASE_0_INSTANT.value))
            self.db.set_state('phase_started_at', datetime.now(timezone.utc).isoformat())
            self.db.set_state('baseline_frozen', 'false')
            self.db.set_state('freeze_until', '')
            self.db.set_state('containment_active', 'false')
            self.db.set_state('containment_until', '')
            self.db.set_state('attack_confidence_score', '0.0')
            self.db.set_state('last_baseline_change', datetime.now(timezone.utc).isoformat())
            self.db.set_state('baseline_item_count', '0')
            logger.info("State initialized to Phase 0 (Instant Safety)")
    
    # ==================== Phase Management ====================
    
    def get_current_phase(self) -> BaselinePhase:
        """Get current baseline phase"""
        phase_value = int(self.db.get_state('phase', '0'))
        return BaselinePhase(phase_value)
    
    def set_phase(self, phase: BaselinePhase):
        """Set baseline phase"""
        self.db.set_state('phase', str(phase.value))
        self.db.set_state('phase_started_at', datetime.now(timezone.utc).isoformat())
        logger.info(f"Entered {phase.name}")
    
    def check_phase_transition(self):
        """
        Check if it's time to transition to next phase.
        Uses SMART transitions based on baseline stability, not just time.
        
        Returns True if phase was advanced
        """
        current_phase = self.get_current_phase()
        phase_started_str = self.db.get_state('phase_started_at')
        
        if not phase_started_str:
            return False
        
        phase_started = datetime.fromisoformat(phase_started_str)
        elapsed = (datetime.now(timezone.utc) - phase_started).total_seconds()
        
        # Get smart transition settings
        smart_mode = self.config.get('baseline', {}).get('smart_transitions', True)
        stability_window = self.config.get('baseline', {}).get('stability_window', 300)  # 5 min default
        
        # Phase 0 → Phase 1 (after 5 minutes OR if we have basic coverage)
        if current_phase == BaselinePhase.PHASE_0_INSTANT:
            min_duration = self.config.get('baseline', {}).get('phase0_duration', 300)
            
            if smart_mode:
                # Transition early if we have basic process coverage
                baselines = self.db.get_baselines(baseline_type='process')
                if len(baselines) >= 10 and elapsed >= 60:  # At least 10 processes and 1 minute
                    logger.info("Smart transition: sufficient initial coverage")
                    self.set_phase(BaselinePhase.PHASE_1_FAST)
                    return True
            
            if elapsed >= min_duration:
                self.set_phase(BaselinePhase.PHASE_1_FAST)
                return True
        
        # Phase 1 → Phase 2 (after stability OR time-based)
        elif current_phase == BaselinePhase.PHASE_1_FAST:
            min_duration = self.config.get('baseline', {}).get('phase1_min_duration', 3600)
            max_duration = self.config.get('baseline', {}).get('phase1_max_duration', 86400)
            min_events = self.config.get('baseline', {}).get('phase1_min_events', 100)
            
            # Count baseline entries
            baselines = self.db.get_baselines()
            total_items = len(baselines)
            event_count = sum(b.observation_count for b in baselines)
            
            if smart_mode:
                # Check if baseline is stable (no new items for stability_window)
                is_stable = self._is_baseline_stable(stability_window)
                
                # Smart transition: stable baseline + minimum coverage
                if is_stable and total_items >= 20 and elapsed >= 300:  # At least 5 min
                    logger.info(f"Smart transition: baseline stable for {stability_window}s with {total_items} items")
                    self.set_phase(BaselinePhase.PHASE_2_EXPANDED)
                    return True
            
            # Time-based fallback
            if (elapsed >= min_duration and event_count >= min_events) or elapsed >= max_duration:
                self.set_phase(BaselinePhase.PHASE_2_EXPANDED)
                return True
        
        # Phase 2 → Phase 3 (after stability OR time-based)
        elif current_phase == BaselinePhase.PHASE_2_EXPANDED:
            min_duration = self.config.get('baseline', {}).get('phase2_min_duration', 7200)
            max_duration = self.config.get('baseline', {}).get('phase2_max_duration', 172800)
            
            if smart_mode:
                # Check for extended stability (2x the normal window)
                is_stable = self._is_baseline_stable(stability_window * 2)
                baselines = self.db.get_baselines()
                
                # Smart transition: very stable + good coverage
                if is_stable and len(baselines) >= 30 and elapsed >= 600:  # At least 10 min
                    logger.info(f"Smart transition: baseline highly stable, entering defending mode")
                    self.set_phase(BaselinePhase.PHASE_3_CONTINUOUS)
                    return True
            
            # Time-based fallback
            if elapsed >= min_duration:
                self.set_phase(BaselinePhase.PHASE_3_CONTINUOUS)
                return True
        
        return False
    
    def _is_baseline_stable(self, stability_window: int = 300) -> bool:
        """
        Check if baseline has been stable (no new items) for the given window.
        
        Args:
            stability_window: Seconds without new baseline items to be considered stable
            
        Returns:
            True if baseline is stable
        """
        last_change_str = self.db.get_state('last_baseline_change')
        if not last_change_str:
            return False
        
        last_change = datetime.fromisoformat(last_change_str)
        elapsed = (datetime.now(timezone.utc) - last_change).total_seconds()
        
        return elapsed >= stability_window
    
    def record_baseline_change(self):
        """
        Record that a new baseline item was added.
        Called by baseline_learner when new items are discovered.
        """
        self.db.set_state('last_baseline_change', datetime.now(timezone.utc).isoformat())
        
        # Update item count
        current_count = int(self.db.get_state('baseline_item_count', '0'))
        self.db.set_state('baseline_item_count', str(current_count + 1))
    
    def get_baseline_stability_info(self) -> Dict[str, Any]:
        """
        Get baseline stability information for status display.
        
        Returns:
            Dict with stability metrics
        """
        last_change_str = self.db.get_state('last_baseline_change', '')
        item_count = int(self.db.get_state('baseline_item_count', '0'))
        
        if last_change_str:
            last_change = datetime.fromisoformat(last_change_str)
            stable_for = (datetime.now(timezone.utc) - last_change).total_seconds()
        else:
            stable_for = 0
        
        stability_window = self.config.get('baseline', {}).get('stability_window', 300)
        is_stable = stable_for >= stability_window
        
        return {
            'last_change': last_change_str,
            'stable_for_seconds': int(stable_for),
            'stability_window': stability_window,
            'is_stable': is_stable,
            'total_items': item_count,
            'ready_to_transition': is_stable and item_count >= 20
        }
    
    def can_take_action(self, action_type: str, confidence_score: float) -> bool:
        """
        Check if action is allowed based on current phase
        
        Args:
            action_type: Type of action
            confidence_score: Confidence score of the detection
            
        Returns:
            True if action is allowed
        """
        current_phase = self.get_current_phase()
        phase_limit = self.config['phase_action_limits'].get(current_phase.value, 100)
        
        # Action is allowed if confidence score is within phase limit
        return confidence_score >= phase_limit or confidence_score >= self.config['confidence']['contain']
    
    # ==================== Baseline Freeze Management ====================
    
    def is_baseline_frozen(self) -> bool:
        """Check if baseline learning is frozen"""
        frozen = self.db.get_state('baseline_frozen', 'false') == 'true'
        
        if frozen:
            # Check if freeze period expired
            freeze_until_str = self.db.get_state('freeze_until', '')
            if freeze_until_str:
                freeze_until = datetime.fromisoformat(freeze_until_str)
                if datetime.now(timezone.utc) > freeze_until:
                    self.unfreeze_baseline()
                    return False
        
        return frozen
    
    def freeze_baseline(self, reason: str = "High confidence attack detected"):
        """
        Freeze baseline learning
        
        Args:
            reason: Reason for freeze
        """
        logger.warning(f"🚨 BASELINE FROZEN: {reason}")
        self.db.set_state('baseline_frozen', 'true')
        
        # Set freeze duration (cooldown period)
        cooldown_seconds = self.config['baseline']['freeze_cooldown']
        freeze_until = datetime.now(timezone.utc) + timedelta(seconds=cooldown_seconds)
        self.db.set_state('freeze_until', freeze_until.isoformat())
        
        self.db.add_audit_log(
            event_type='baseline_freeze',
            actor='system',
            target='baseline_learning',
            details={'reason': reason, 'freeze_until': freeze_until.isoformat()}
        )
    
    def unfreeze_baseline(self):
        """Unfreeze baseline learning"""
        logger.info("✅ Baseline learning resumed")
        self.db.set_state('baseline_frozen', 'false')
        self.db.set_state('freeze_until', '')
        
        self.db.add_audit_log(
            event_type='baseline_unfreeze',
            actor='system',
            target='baseline_learning',
            details={'resumed_at': datetime.now(timezone.utc).isoformat()}
        )
    
    # ==================== Attack Confidence Tracking ====================
    
    def update_attack_confidence(self, score: float):
        """
        Update current attack confidence score
        
        Args:
            score: New confidence score
        """
        current_score = float(self.db.get_state('attack_confidence_score', '0.0'))
        
        # Use max of current and new score (decay over time handled elsewhere)
        if score > current_score:
            self.db.set_state('attack_confidence_score', str(score))
            
            # Freeze baseline if score exceeds contain threshold
            if self.config['baseline']['freeze_on_attack']:
                contain_threshold = self.config['confidence']['contain']
                if score >= contain_threshold and not self.is_baseline_frozen():
                    self.freeze_baseline(f"Attack confidence score: {score}")
    
    def get_attack_confidence(self) -> float:
        """Get current attack confidence score"""
        return float(self.db.get_state('attack_confidence_score', '0.0'))
    
    def decay_attack_confidence(self, decay_amount: float = 1.0):
        """
        Gradually decay attack confidence over time
        
        Args:
            decay_amount: Amount to decay (called periodically)
        """
        current = self.get_attack_confidence()
        new_score = max(0.0, current - decay_amount)
        self.db.set_state('attack_confidence_score', str(new_score))
    
    # ==================== Containment Mode ====================
    
    def is_containment_active(self) -> bool:
        """Check if containment mode is active"""
        active = self.db.get_state('containment_active', 'false') == 'true'
        
        if active:
            # Check if containment period expired
            until_str = self.db.get_state('containment_until', '')
            if until_str:
                until = datetime.fromisoformat(until_str)
                if datetime.now(timezone.utc) > until:
                    self.disable_containment_mode()
                    return False
        
        return active
    
    def enable_containment_mode(self, duration_seconds: Optional[int] = None):
        """
        Enable containment mode
        
        Args:
            duration_seconds: Duration in seconds (uses config default if None)
        """
        if duration_seconds is None:
            duration_seconds = self.config['containment']['default_duration']
        
        max_duration = self.config['containment']['max_duration']
        duration_seconds = min(duration_seconds, max_duration)
        
        until = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
        
        logger.warning(f"🔒 CONTAINMENT MODE ENABLED until {until.isoformat()}")
        self.db.set_state('containment_active', 'true')
        self.db.set_state('containment_until', until.isoformat())
        
        self.db.add_audit_log(
            event_type='containment_enable',
            actor='system',
            target='system',
            details={'duration_seconds': duration_seconds, 'until': until.isoformat()}
        )
    
    def disable_containment_mode(self):
        """Disable containment mode"""
        logger.info("🔓 Containment mode disabled")
        self.db.set_state('containment_active', 'false')
        self.db.set_state('containment_until', '')
        
        self.db.add_audit_log(
            event_type='containment_disable',
            actor='system',
            target='system',
            details={'disabled_at': datetime.now(timezone.utc).isoformat()}
        )
    
    def extend_containment(self, additional_seconds: int):
        """
        Extend containment mode duration
        
        Args:
            additional_seconds: Seconds to add
        """
        if not self.is_containment_active():
            logger.warning("Cannot extend containment - not currently active")
            return
        
        until_str = self.db.get_state('containment_until', '')
        if until_str:
            current_until = datetime.fromisoformat(until_str)
            new_until = current_until + timedelta(seconds=additional_seconds)
            
            # Respect max duration
            max_until = datetime.now(timezone.utc) + timedelta(seconds=self.config['containment']['max_duration'])
            new_until = min(new_until, max_until)
            
            self.db.set_state('containment_until', new_until.isoformat())
            logger.info(f"Containment extended until {new_until.isoformat()}")
    
    # ==================== General State ====================
    
    def get_state_summary(self) -> Dict[str, Any]:
        """Get complete state summary"""
        return {
            'phase': self.get_current_phase().name,
            'phase_value': self.get_current_phase().value,
            'phase_started_at': self.db.get_state('phase_started_at'),
            'baseline_frozen': self.is_baseline_frozen(),
            'freeze_until': self.db.get_state('freeze_until'),
            'attack_confidence': self.get_attack_confidence(),
            'containment_active': self.is_containment_active(),
            'containment_until': self.db.get_state('containment_until'),
        }
