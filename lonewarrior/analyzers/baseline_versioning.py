"""
Baseline Versioning - Track and compare baseline versions
"""

import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Baseline, BaselinePhase
from lonewarrior.core.event_bus import EventBus, EventPriority


logger = logging.getLogger(__name__)


@dataclass
class BaselineVersion:
    """Represents a versioned baseline snapshot"""
    version: int
    created_at: datetime
    phase: int
    baseline_type: str
    key: str
    profile: Dict[str, Any]
    observation_count: int


class BaselineVersionManager:
    """
    Manages baseline versioning and comparison.
    
    Features:
    - Store baseline versions at phase transitions
    - Compare current vs historical baselines
    - Detect baseline drift
    - Rollback to previous baseline version
    """
    
    def __init__(self, config: Dict[str, Any], database: Database,
                 event_bus: EventBus):
        self.config = config
        self.db = database
        self.event_bus = event_bus
        
        # Version history (in-memory cache)
        self.version_history: Dict[str, List[BaselineVersion]] = {}
        
        # Settings
        self.max_versions = config.get('baseline', {}).get('max_versions', 10)
        self.drift_threshold = config.get('baseline', {}).get('drift_threshold', 0.3)
        
        # Subscribe to phase changes
        self.event_bus.subscribe('phase_changed', self.handle_phase_change)
    
    def start(self):
        """Start baseline version manager"""
        logger.info("Baseline version manager started")
    
    def stop(self):
        """Stop baseline version manager"""
        logger.info("Baseline version manager stopped")
    
    def handle_phase_change(self, event):
        """Create baseline snapshot on phase change"""
        data = event.data
        new_phase = data.get('phase', 0)
        
        logger.info(f"Phase changed to {new_phase}, creating baseline snapshot")
        self.create_snapshot(new_phase)
    
    def create_snapshot(self, phase: int) -> int:
        """
        Create a snapshot of all current baselines.
        
        Args:
            phase: Current phase at snapshot time
            
        Returns:
            Number of baselines snapshotted
        """
        baselines = self.db.get_baselines()
        count = 0
        
        for baseline in baselines:
            key = f"{baseline.baseline_type}:{baseline.key}"
            
            # Create version entry
            version = BaselineVersion(
                version=baseline.version,
                created_at=datetime.now(timezone.utc),
                phase=phase,
                baseline_type=baseline.baseline_type,
                key=baseline.key,
                profile=baseline.profile,
                observation_count=baseline.observation_count
            )
            
            # Store in history
            if key not in self.version_history:
                self.version_history[key] = []
            
            self.version_history[key].append(version)
            
            # Trim old versions
            if len(self.version_history[key]) > self.max_versions:
                self.version_history[key] = self.version_history[key][-self.max_versions:]
            
            count += 1
        
        logger.info(f"Created snapshot of {count} baselines at phase {phase}")
        
        # Persist to database
        self._persist_snapshot(phase)
        
        return count
    
    def compare_versions(self, baseline_type: str, key: str,
                        version1: int, version2: int) -> Dict[str, Any]:
        """
        Compare two versions of a baseline.
        
        Args:
            baseline_type: Type of baseline
            key: Baseline key
            version1: First version number
            version2: Second version number
            
        Returns:
            Comparison result with drift metrics
        """
        full_key = f"{baseline_type}:{key}"
        
        if full_key not in self.version_history:
            return {'error': 'Baseline not found in history'}
        
        history = self.version_history[full_key]
        
        v1 = next((v for v in history if v.version == version1), None)
        v2 = next((v for v in history if v.version == version2), None)
        
        if not v1 or not v2:
            return {'error': 'Version not found'}
        
        # Calculate drift
        drift = self._calculate_drift(v1.profile, v2.profile)
        
        return {
            'baseline_type': baseline_type,
            'key': key,
            'version1': version1,
            'version2': version2,
            'drift': drift,
            'is_significant': drift > self.drift_threshold,
            'v1_observations': v1.observation_count,
            'v2_observations': v2.observation_count,
            'time_delta': (v2.created_at - v1.created_at).total_seconds()
        }
    
    def detect_drift(self, baseline_type: str, key: str) -> Optional[Dict[str, Any]]:
        """
        Detect if current baseline has drifted from historical.
        
        Args:
            baseline_type: Type of baseline
            key: Baseline key
            
        Returns:
            Drift detection result or None if no drift
        """
        current = self.db.get_baseline(baseline_type, key)
        if not current:
            return None
        
        full_key = f"{baseline_type}:{key}"
        
        if full_key not in self.version_history or len(self.version_history[full_key]) < 2:
            return None
        
        # Compare with oldest version
        oldest = self.version_history[full_key][0]
        
        drift = self._calculate_drift(oldest.profile, current.profile)
        
        if drift > self.drift_threshold:
            return {
                'baseline_type': baseline_type,
                'key': key,
                'drift': drift,
                'threshold': self.drift_threshold,
                'oldest_version': oldest.version,
                'current_version': current.version,
                'time_span': (datetime.now(timezone.utc) - oldest.created_at).total_seconds()
            }
        
        return None
    
    def rollback_baseline(self, baseline_type: str, key: str, 
                         target_version: int) -> bool:
        """
        Rollback a baseline to a previous version.
        
        Args:
            baseline_type: Type of baseline
            key: Baseline key
            target_version: Version to rollback to
            
        Returns:
            True if rollback successful
        """
        full_key = f"{baseline_type}:{key}"
        
        if full_key not in self.version_history:
            logger.error(f"Baseline {full_key} not found in history")
            return False
        
        target = next((v for v in self.version_history[full_key] 
                      if v.version == target_version), None)
        
        if not target:
            logger.error(f"Version {target_version} not found for {full_key}")
            return False
        
        # Create new baseline with old profile
        baseline = Baseline(
            baseline_type=baseline_type,
            key=key,
            phase=target.phase,
            profile=target.profile,
            observation_count=target.observation_count,
            version=target.version
        )
        
        self.db.upsert_baseline(baseline)
        
        logger.info(f"Rolled back {full_key} to version {target_version}")
        
        return True
    
    def get_baseline_history(self, baseline_type: str, key: str) -> List[Dict[str, Any]]:
        """
        Get version history for a baseline.
        
        Args:
            baseline_type: Type of baseline
            key: Baseline key
            
        Returns:
            List of version info dictionaries
        """
        full_key = f"{baseline_type}:{key}"
        
        if full_key not in self.version_history:
            return []
        
        return [
            {
                'version': v.version,
                'created_at': v.created_at.isoformat(),
                'phase': v.phase,
                'observation_count': v.observation_count
            }
            for v in self.version_history[full_key]
        ]
    
    def _calculate_drift(self, profile1: Dict[str, Any], 
                        profile2: Dict[str, Any]) -> float:
        """
        Calculate drift between two profiles.
        
        Uses normalized difference for numeric values and
        Jaccard similarity for sets/lists.
        
        Returns:
            Drift score (0.0 = identical, 1.0 = completely different)
        """
        if not profile1 or not profile2:
            return 1.0 if profile1 or profile2 else 0.0
        
        all_keys = set(profile1.keys()) | set(profile2.keys())
        
        if not all_keys:
            return 0.0
        
        total_drift = 0.0
        key_count = 0
        
        for key in all_keys:
            v1 = profile1.get(key)
            v2 = profile2.get(key)
            
            if v1 is None or v2 is None:
                total_drift += 1.0
            elif isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
                # Numeric comparison
                if max(abs(v1), abs(v2)) > 0:
                    total_drift += abs(v1 - v2) / max(abs(v1), abs(v2))
            elif isinstance(v1, list) and isinstance(v2, list):
                # List comparison (Jaccard)
                s1, s2 = set(v1), set(v2)
                if s1 or s2:
                    total_drift += 1.0 - len(s1 & s2) / len(s1 | s2)
            elif isinstance(v1, dict) and isinstance(v2, dict):
                # Recursive dict comparison
                total_drift += self._calculate_drift(v1, v2)
            else:
                # Simple equality
                total_drift += 0.0 if v1 == v2 else 1.0
            
            key_count += 1
        
        return total_drift / key_count if key_count > 0 else 0.0
    
    def _persist_snapshot(self, phase: int):
        """Persist snapshot to database"""
        snapshot_data = {}
        
        for key, versions in self.version_history.items():
            if versions:
                latest = versions[-1]
                snapshot_data[key] = {
                    'version': latest.version,
                    'phase': latest.phase,
                    'observation_count': latest.observation_count,
                    'created_at': latest.created_at.isoformat()
                }
        
        self.db.set_state(
            f'baseline_snapshot_phase_{phase}',
            json.dumps(snapshot_data)
        )
    
    def get_drift_report(self) -> List[Dict[str, Any]]:
        """
        Generate drift report for all baselines.
        
        Returns:
            List of baselines with detected drift
        """
        report = []
        
        for full_key in self.version_history:
            baseline_type, key = full_key.split(':', 1)
            drift_result = self.detect_drift(baseline_type, key)
            
            if drift_result:
                report.append(drift_result)
        
        # Sort by drift magnitude
        report.sort(key=lambda x: x['drift'], reverse=True)
        
        return report
