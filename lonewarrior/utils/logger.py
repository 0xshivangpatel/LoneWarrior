"""Logging utilities for LoneWarrior"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from pythonjsonlogger import jsonlogger
from typing import Dict, Any


def setup_logging(config: Dict[str, Any]):
    """
    Setup logging configuration
    
    Args:
        config: Configuration dictionary
    """
    log_level = getattr(logging, config['general']['log_level'].upper(), logging.INFO)
    log_dir = Path(config['general']['log_dir'])
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with colored output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        log_dir / 'lonewarrior.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(console_format)
    root_logger.addHandler(file_handler)
    
    # JSON structured logging for audit trail
    audit_handler = RotatingFileHandler(
        log_dir / 'audit.jsonl',
        maxBytes=50 * 1024 * 1024,  # 50MB
        backupCount=10
    )
    audit_handler.setLevel(logging.INFO)
    json_format = jsonlogger.JsonFormatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s'
    )
    audit_handler.setFormatter(json_format)
    
    # Audit logger
    audit_logger = logging.getLogger('lonewarrior.audit')
    audit_logger.addHandler(audit_handler)
    audit_logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """Get logger instance"""
    return logging.getLogger(f"lonewarrior.{name}")


def audit_log(event_type: str, data: Dict[str, Any]):
    """
    Log an audit event
    
    Args:
        event_type: Type of event (detection, action, feedback, etc.)
        data: Event data dictionary
    """
    audit_logger = logging.getLogger('lonewarrior.audit')
    audit_logger.info(f"{event_type}", extra={'event_data': data})
