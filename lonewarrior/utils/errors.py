"""
Consistent error handling utilities for LoneWarrior.

Provides standardized exceptions and error handling patterns
to ensure consistent behavior across the codebase.
"""

import logging
import functools
from typing import Callable, TypeVar, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels for categorization"""
    LOW = "low"           # Minor issues, operation continues
    MEDIUM = "medium"     # Significant issue, may affect functionality
    HIGH = "high"         # Critical issue, component may fail
    CRITICAL = "critical" # System-wide impact, requires attention


class LoneWarriorError(Exception):
    """Base exception for all LoneWarrior errors"""

    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 component: Optional[str] = None, cause: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.component = component
        self.cause = cause

    def __str__(self):
        parts = [self.message]
        if self.component:
            parts.insert(0, f"[{self.component}]")
        if self.cause:
            parts.append(f"(caused by: {self.cause})")
        return " ".join(parts)


class ConfigurationError(LoneWarriorError):
    """Configuration-related errors"""
    pass


class CollectorError(LoneWarriorError):
    """Collector-related errors"""
    pass


class AnalyzerError(LoneWarriorError):
    """Analyzer-related errors"""
    pass


class ResponderError(LoneWarriorError):
    """Responder/action-related errors"""
    pass


class DatabaseError(LoneWarriorError):
    """Database operation errors"""
    pass


class PrivilegeError(LoneWarriorError):
    """Privilege/permission errors"""
    pass


class ValidationError(LoneWarriorError):
    """Input validation errors"""
    pass


T = TypeVar('T')


def handle_error(
    error: Exception,
    component: str,
    operation: str,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    reraise: bool = False,
    default_return: Any = None
) -> Any:
    """
    Standardized error handling with consistent logging.

    Args:
        error: The exception that occurred
        component: Name of the component where error occurred
        operation: Description of the operation that failed
        severity: Error severity level
        reraise: Whether to re-raise the exception
        default_return: Value to return if not reraising

    Returns:
        default_return if not reraising

    Raises:
        LoneWarriorError if reraise is True
    """
    # Log based on severity
    log_message = f"[{component}] {operation} failed: {error}"

    if severity == ErrorSeverity.CRITICAL:
        logger.critical(log_message, exc_info=True)
    elif severity == ErrorSeverity.HIGH:
        logger.error(log_message, exc_info=True)
    elif severity == ErrorSeverity.MEDIUM:
        logger.warning(log_message)
    else:  # LOW
        logger.debug(log_message)

    if reraise:
        if isinstance(error, LoneWarriorError):
            raise error
        raise LoneWarriorError(
            message=f"{operation} failed",
            severity=severity,
            component=component,
            cause=error
        )

    return default_return


def safe_operation(
    component: str,
    operation: str,
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    default_return: Any = None,
    reraise: bool = False
) -> Callable:
    """
    Decorator for safe operation execution with consistent error handling.

    Usage:
        @safe_operation("ProcessCollector", "collect processes")
        def collect(self):
            ...
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                return handle_error(
                    error=e,
                    component=component,
                    operation=operation,
                    severity=severity,
                    reraise=reraise,
                    default_return=default_return
                )
        return wrapper
    return decorator


def log_and_continue(
    error: Exception,
    component: str,
    operation: str,
    severity: ErrorSeverity = ErrorSeverity.LOW
) -> None:
    """
    Log an error and continue execution.
    Use for non-critical errors that shouldn't stop operation.
    """
    handle_error(
        error=error,
        component=component,
        operation=operation,
        severity=severity,
        reraise=False
    )
