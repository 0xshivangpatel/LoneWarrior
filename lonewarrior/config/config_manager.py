"""Configuration management for LoneWarrior"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional


logger = logging.getLogger(__name__)


class ConfigManager:
    """Manages configuration loading and validation"""

    # Config search order: local first (for development), then user, then system
    # This allows easy local overrides without modifying system config
    DEFAULT_CONFIG_PATHS = [
        "./config.yaml",
        "~/.config/lonewarrior/config.yaml",
        "/etc/lonewarrior/config.yaml",
    ]
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Optional path to user config file
        """
        self.config_path = config_path
        self.config: Dict[str, Any] = {}
        
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from defaults and user overrides
        
        Returns:
            Complete configuration dictionary
        """
        # Start with default configuration
        defaults_path = Path(__file__).parent / "defaults.yaml"
        self.config = self._load_yaml(defaults_path)
        
        if not self.config:
            raise RuntimeError("Failed to load default configuration")
        
        # Find and load user configuration if it exists
        user_config_path = self._find_user_config()
        if user_config_path:
            logger.info(f"Loading user configuration from: {user_config_path}")
            user_config = self._load_yaml(user_config_path)
            self.config = self._merge_configs(self.config, user_config)
        else:
            logger.info("No user configuration found, using defaults")
        
        # Apply environment variable overrides
        self._apply_env_overrides()
        
        # Validate configuration
        self._validate_config()
        
        return self.config
    
    def _find_user_config(self) -> Optional[Path]:
        """Find user configuration file"""
        # If explicitly specified, use that
        if self.config_path:
            path = Path(self.config_path).expanduser()
            if path.exists():
                return path
            else:
                logger.warning(f"Specified config file not found: {self.config_path}")
                return None
        
        # Otherwise search default locations
        for config_path in self.DEFAULT_CONFIG_PATHS:
            path = Path(config_path).expanduser()
            if path.exists():
                return path
        
        return None
    
    def _load_yaml(self, path: Path) -> Dict[str, Any]:
        """Load YAML file"""
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Failed to load config from {path}: {e}")
            return {}
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge override config into base config
        
        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary
            
        Returns:
            Merged configuration
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                result[key] = self._merge_configs(result[key], value)
            else:
                # Override value
                result[key] = value
        
        return result
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides"""
        # LW_LOG_LEVEL
        if 'LW_LOG_LEVEL' in os.environ:
            self.config['general']['log_level'] = os.environ['LW_LOG_LEVEL']

        # LW_DATA_DIR
        if 'LW_DATA_DIR' in os.environ:
            self.config['general']['data_dir'] = os.environ['LW_DATA_DIR']

        # LW_LOG_DIR
        if 'LW_LOG_DIR' in os.environ:
            self.config['general']['log_dir'] = os.environ['LW_LOG_DIR']

        # LW_WEB_ENABLED
        if 'LW_WEB_ENABLED' in os.environ:
            self.config['web_dashboard']['enabled'] = os.environ['LW_WEB_ENABLED'].lower() in ('true', '1', 'yes')

        # LW_PRIVILEGE_MODE: none, helper, root (for privilege separation)
        if 'LW_PRIVILEGE_MODE' in os.environ:
            mode = os.environ['LW_PRIVILEGE_MODE'].lower()
            if mode in ('none', 'helper', 'root'):
                self.config.setdefault('security', {})['privilege_mode'] = mode
    
    def _validate_config(self):
        """Validate configuration values"""
        # Ensure required directories exist or can be created
        data_dir = Path(self.config['general']['data_dir'])
        log_dir = Path(self.config['general']['log_dir'])
        
        for dir_path in [data_dir, log_dir]:
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                    logger.info(f"Created directory: {dir_path}")
                except Exception as e:
                    logger.warning(f"Could not create directory {dir_path}: {e}")
        
        # Validate phase durations
        baseline = self.config['baseline']
        if baseline['phase1_min_duration'] > baseline['phase1_max_duration']:
            raise ValueError("Phase 1 min duration cannot exceed max duration")
        
        # Validate confidence thresholds
        thresholds = self.config['confidence']
        if not (0 <= thresholds['observe'] < thresholds['contain'] < thresholds['aggressive'] < thresholds['lockdown'] <= 100):
            raise ValueError("Invalid confidence threshold ordering")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-separated key path
        
        Args:
            key_path: Dot-separated path (e.g., 'baseline.phase1_duration')
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, key_path: str, value: Any):
        """
        Set configuration value by dot-separated key path
        
        Args:
            key_path: Dot-separated path
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to parent
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set value
        config[keys[-1]] = value
    
    def save_user_config(self, path: Optional[str] = None):
        """
        Save current configuration to user config file
        
        Args:
            path: Optional path to save to (uses default if not specified)
        """
        if path is None:
            path = "/etc/lonewarrior/config.yaml"
        
        save_path = Path(path).expanduser()
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            logger.info(f"Configuration saved to: {save_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise
