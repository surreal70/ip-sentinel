"""
IP Classification Module (Module 1) for categorizing IP addresses.
"""

import ipaddress
from ipaddress import IPv4Address, IPv6Address
from typing import Dict, List, Optional, Union

from ..config import ConfigManager, ClassificationRule

# Type alias for IP addresses
IPAddress = Union[IPv4Address, IPv6Address]


class ClassificationModule:
    """Module for classifying IP addresses based on RFC standards and custom rules."""

    def __init__(self, config_manager: Optional[ConfigManager] = None):
        """Initialize the classification module."""
        self.config_manager = config_manager or ConfigManager()

    def classify_ip(self, ip: IPAddress) -> List[Dict]:
        """
        Classify an IP address according to RFC standards and custom rules.

        Args:
            ip: IPAddress object to classify

        Returns:
            List of classification dictionaries
        """
        classifications = []
        rules = self.config_manager.load_classifications()

        # Check each classification rule
        for rule_name, rule in rules.items():
            try:
                network = ipaddress.ip_network(rule.ip_range, strict=False)
                if ip in network:
                    # Skip the broad public ranges unless no other match found
                    if rule_name in ["public_ipv4", "public_ipv6"]:
                        continue

                    classifications.append({
                        "name": rule.name,
                        "ip_range": rule.ip_range,
                        "description": rule.description,
                        "qualifies_for": rule.qualifies_for,
                        "rfc_reference": rule.rfc_reference
                    })
            except ValueError:
                # Skip invalid IP ranges
                continue

        # If no specific classification found, use the appropriate public range
        if not classifications:
            public_rule_name = "public_ipv6" if ip.version == 6 else "public_ipv4"
            if public_rule_name in rules:
                rule = rules[public_rule_name]
                classifications.append({
                    "name": rule.name,
                    "ip_range": rule.ip_range,
                    "description": rule.description,
                    "qualifies_for": rule.qualifies_for,
                    "rfc_reference": rule.rfc_reference
                })

        return classifications

    def get_qualified_modules(self, classifications: List[Dict]) -> List[str]:
        """
        Determine which modules should run based on classifications.

        Args:
            classifications: List of classification results

        Returns:
            List of module names that should be executed
        """
        qualified_modules = set()

        for classification in classifications:
            qualified_modules.update(classification.get("qualifies_for", []))

        return list(qualified_modules)

    def create_default_classifications(self) -> Dict[str, ClassificationRule]:
        """
        Create default RFC-compliant IP range classifications.

        Returns:
            Dictionary of default classification rules
        """
        return self.config_manager._create_default_classifications()
