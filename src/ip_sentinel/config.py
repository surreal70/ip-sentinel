"""
Configuration management for IP-Sentinel.
"""

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Any
import ipaddress


@dataclass
class ClassificationRule:
    """Represents an IP classification rule."""
    name: str
    ip_range: str
    description: str
    qualifies_for: List[str]
    rfc_reference: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClassificationRule':
        """Create from dictionary loaded from JSON."""
        return cls(**data)


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

    # Privilege settings
    run_root: bool = False

    # SSL certificate verification
    verify_ssl: bool = True

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

    def __init__(
            self,
            config_path: Optional[Path] = None,
            classifications_path: Optional[Path] = None):
        """Initialize configuration manager."""
        self.config_path = config_path or Path("config.json")
        self.classifications_path = classifications_path or Path("classifications.json")

    def load_config(self) -> Config:
        """Load configuration from file or create default."""
        if not self.config_path.exists():
            return Config()

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Convert database_path string back to Path if present
            if data.get('database_path'):
                data['database_path'] = Path(data['database_path'])

            return Config(**data)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            raise ValueError(f"Invalid configuration file format: {e}")

    def save_config(self, config: Config) -> None:
        """Save configuration to file."""
        data = asdict(config)

        # Convert Path objects to strings for JSON serialization
        if data.get('database_path'):
            data['database_path'] = str(data['database_path'])

        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except (OSError, IOError) as e:
            raise ValueError(f"Failed to save configuration: {e}")

    def load_classifications(self) -> Dict[str, ClassificationRule]:
        """Load IP classification rules from JSON file."""
        if not self.classifications_path.exists():
            # Create default classifications on first run
            default_rules = self._create_default_classifications()
            self.save_classifications(default_rules)
            return default_rules

        try:
            with open(self.classifications_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            rules = {}
            for name, rule_data in data.items():
                rules[name] = ClassificationRule.from_dict(rule_data)

            return rules
        except (json.JSONDecodeError, TypeError, ValueError, KeyError) as e:
            raise ValueError(f"Invalid classifications file format: {e}")

    def save_classifications(self, rules: Dict[str, ClassificationRule]) -> None:
        """Save IP classification rules to JSON file."""
        data = {}
        for name, rule in rules.items():
            data[name] = rule.to_dict()

        try:
            with open(self.classifications_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except (OSError, IOError) as e:
            raise ValueError(f"Failed to save classifications: {e}")

    def add_classification(self, rule: ClassificationRule) -> None:
        """Add a new classification rule."""
        # Validate IP range format
        try:
            ipaddress.ip_network(rule.ip_range, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid IP range format '{rule.ip_range}': {e}")

        # Validate qualifies_for modules
        valid_modules = ["local_info", "internet_info", "netbox", "checkmk",
                         "openitcockpit", "openvas", "infoblox"]
        for module in rule.qualifies_for:
            if module not in valid_modules:
                raise ValueError(f"Invalid module name '{module}' in qualifies_for")

        rules = self.load_classifications()
        rules[rule.name] = rule
        self.save_classifications(rules)

    def remove_classification(self, rule_name: str) -> bool:
        """Remove a classification rule by name."""
        rules = self.load_classifications()
        if rule_name not in rules:
            return False

        del rules[rule_name]
        self.save_classifications(rules)
        return True

    def update_classification(
            self,
            rule_name: str,
            updated_rule: ClassificationRule) -> bool:
        """Update an existing classification rule."""
        rules = self.load_classifications()
        if rule_name not in rules:
            return False

        # Validate the updated rule
        try:
            ipaddress.ip_network(updated_rule.ip_range, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid IP range format '{updated_rule.ip_range}': {e}")

        valid_modules = ["local_info", "internet_info", "netbox", "checkmk",
                         "openitcockpit", "openvas", "infoblox"]
        for module in updated_rule.qualifies_for:
            if module not in valid_modules:
                raise ValueError(f"Invalid module name '{module}' in qualifies_for")

        # Remove old rule and add updated one
        del rules[rule_name]
        rules[updated_rule.name] = updated_rule
        self.save_classifications(rules)
        return True

    def _create_default_classifications(self) -> Dict[str, ClassificationRule]:
        """Create default RFC-compliant IP range classifications."""
        default_rules = {
            "private_ipv4_10": ClassificationRule(
                name="private_ipv4_10",
                ip_range="10.0.0.0/8",
                description="Private IPv4 addresses (Class A)",
                qualifies_for=["local_info"],
                rfc_reference="RFC 1918"
            ),
            "private_ipv4_172": ClassificationRule(
                name="private_ipv4_172",
                ip_range="172.16.0.0/12",
                description="Private IPv4 addresses (Class B)",
                qualifies_for=["local_info"],
                rfc_reference="RFC 1918"
            ),
            "private_ipv4_192": ClassificationRule(
                name="private_ipv4_192",
                ip_range="192.168.0.0/16",
                description="Private IPv4 addresses (Class C)",
                qualifies_for=["local_info"],
                rfc_reference="RFC 1918"
            ),
            "localhost_ipv4": ClassificationRule(
                name="localhost_ipv4",
                ip_range="127.0.0.0/8",
                description="IPv4 loopback addresses",
                qualifies_for=["local_info"],
                rfc_reference="RFC 1122"
            ),
            "link_local_ipv4": ClassificationRule(
                name="link_local_ipv4",
                ip_range="169.254.0.0/16",
                description="IPv4 link-local addresses",
                qualifies_for=["local_info"],
                rfc_reference="RFC 3927"
            ),
            "multicast_ipv4": ClassificationRule(
                name="multicast_ipv4",
                ip_range="224.0.0.0/4",
                description="IPv4 multicast addresses",
                qualifies_for=[],
                rfc_reference="RFC 1112"
            ),
            "broadcast_ipv4": ClassificationRule(
                name="broadcast_ipv4",
                ip_range="255.255.255.255/32",
                description="IPv4 limited broadcast address",
                qualifies_for=[],
                rfc_reference="RFC 919"
            ),
            "private_ipv6_unique_local": ClassificationRule(
                name="private_ipv6_unique_local",
                ip_range="fc00::/7",
                description="IPv6 unique local addresses",
                qualifies_for=["local_info"],
                rfc_reference="RFC 4193"
            ),
            "localhost_ipv6": ClassificationRule(
                name="localhost_ipv6",
                ip_range="::1/128",
                description="IPv6 loopback address",
                qualifies_for=["local_info"],
                rfc_reference="RFC 4291"
            ),
            "link_local_ipv6": ClassificationRule(
                name="link_local_ipv6",
                ip_range="fe80::/10",
                description="IPv6 link-local addresses",
                qualifies_for=["local_info"],
                rfc_reference="RFC 4291"
            ),
            "multicast_ipv6": ClassificationRule(
                name="multicast_ipv6",
                ip_range="ff00::/8",
                description="IPv6 multicast addresses",
                qualifies_for=[],
                rfc_reference="RFC 4291"
            ),
            "public_ipv4": ClassificationRule(
                name="public_ipv4",
                ip_range="0.0.0.0/0",
                description="Public IPv4 addresses (default for unmatched)",
                qualifies_for=["local_info", "internet_info"],
                rfc_reference="RFC 791"
            ),
            "public_ipv6": ClassificationRule(
                name="public_ipv6",
                ip_range="::/0",
                description="Public IPv6 addresses (default for unmatched)",
                qualifies_for=["local_info", "internet_info"],
                rfc_reference="RFC 4291"
            )
        }

        return default_rules
