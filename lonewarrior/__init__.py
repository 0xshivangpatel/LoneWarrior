"""
LoneWarrior - Autonomous Security Agent
Version 1.0.0
"""

__version__ = "1.0.0"
__author__ = "LoneWarrior Contributors"
__license__ = "Apache 2.0"

# Package-level imports for convenience
from lonewarrior.core.engine import SecurityEngine
from lonewarrior.core.state_manager import StateManager, BaselinePhase

__all__ = [
    "__version__",
    "SecurityEngine",
    "StateManager",
    "BaselinePhase",
]
