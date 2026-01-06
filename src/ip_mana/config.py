"""
Configuration management for IP Intelligence Analyzer.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


@dataclass
class Config:
    """Configuration container for the application."""

    # Database settings
    database_path: Optional[Path] = None

    # Output settings
    output_format: str = "human"  # human, json, html
    reporting_mode: str = "dense"  # dense, full, full-err

    # Module settings
    force_internet: bool = False
    enabled_modules: Dict[str, bool] = None

    # Verbosity
    verbose: bool = False

    def __post_init__(self):
        """Initialize default values after dataclass creation."""
        if self.enabled_modules is None:
            self.enabled_modules = {
                "classification": True,
                "local_info": True,
                "internet_info": True,
                "netbox": False,
                "checkmk": False,
                "openitcockpit": False,
                "openvas": False,
                "infoblox": False,
            }


class ConfigManager:
    """Manages application configuration and classification rules."""

    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration manager."""
        self.config_path = config_path or Path("config.json")

    def load_config(self) -> Config:
        """Load configuration from file or create default."""
        # TODO: Implement configuration file loading
        return Config()

    def save_config(self, config: Config) -> None:
        """Save configuration to file."""
        # TODO: Implement configuration file saving
        pass

    def load_classifications(self) -> Dict[str, Dict]:
        """Load IP classification rules from JSON file."""
        # TODO: Implement classification loading
        return {}

    def save_classifications(self, rules: Dict[str, Dict]) -> None:
        """Save IP classification rules to JSON file."""
        # TODO: Implement classification saving
        pass
