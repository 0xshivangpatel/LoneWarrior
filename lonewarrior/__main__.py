"""
Main entry point for LoneWarrior daemon
Run with: python -m lonewarrior
"""

import sys
import os
import argparse
import atexit
import logging
import signal
from pathlib import Path

from lonewarrior.core.engine import SecurityEngine
from lonewarrior.config.config_manager import ConfigManager
from lonewarrior.utils.logger import setup_logging


# Global reference for cleanup
_pid_file: Path = None
_engine: SecurityEngine = None


def _cleanup_pid_file():
    """Remove PID file on exit"""
    global _pid_file
    if _pid_file and _pid_file.exists():
        try:
            _pid_file.unlink()
        except Exception:
            pass


def _create_pid_file(config: dict) -> Path:
    """Create PID file to indicate daemon is running"""
    global _pid_file
    pid_dir = Path(config['general']['data_dir'])
    pid_dir.mkdir(parents=True, exist_ok=True)
    _pid_file = pid_dir / 'lonewarrior.pid'
    _pid_file.write_text(str(os.getpid()))
    atexit.register(_cleanup_pid_file)
    return _pid_file


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global _engine
    logger = logging.getLogger(__name__)
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    if _engine:
        _engine.stop()
    sys.exit(0)


def main():
    """Main entry point for daemon"""
    global _engine

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='LoneWarrior Security Agent')
    parser.add_argument('--config', '-c', type=str, help='Path to config file')
    parser.add_argument('command', nargs='?', default='daemon', help='Command to run')
    args = parser.parse_args()

    # Setup signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Load configuration
    config_manager = ConfigManager(config_path=args.config)
    config = config_manager.load_config()

    # Setup logging
    setup_logging(config)
    logger = logging.getLogger(__name__)

    # Create PID file
    pid_file = _create_pid_file(config)
    logger.info(f"PID file created: {pid_file}")

    logger.info("=" * 60)
    logger.info("LoneWarrior - Autonomous Security Agent v1.0.0")
    logger.info("=" * 60)

    try:
        # Initialize and start the security engine
        _engine = SecurityEngine(config)
        logger.info("Security engine initialized successfully")

        # Start the engine (blocking call)
        _engine.start()

    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
    except Exception as e:
        logger.critical(f"Fatal error in main: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if _engine:
            _engine.stop()
        _cleanup_pid_file()
        logger.info("LoneWarrior shutdown complete")


if __name__ == "__main__":
    main()
