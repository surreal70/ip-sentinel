"""
Property-based tests for IP classification consistency.

**Feature: ip-intelligence-analyzer, Property 11: Classification Consistency**
**Validates: Requirements 6.3, 6.4, 6.5**
"""

import ipaddress
import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, assume
from hypothesis.strategies import composite

from src.ip_mana.config import ConfigManager, ClassificationRule
from src.ip_mana.modules.classification import ClassificationModule


@composite
def valid_ipv4_addresses(draw):
    """Generate valid IPv4 addresses."""
    octets = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
    return ipaddress.IPv4Address('.'.join(map(str, octets)))


@composite
def valid_ipv6_addresses(draw):
    """Generate valid IPv6 addresses."""
    groups = [draw(st.integers(min_value=0, max_value=0xFFFF)) for _ in range(8)]
    return ipaddress.IPv6Address(':'.join(f'{g:x}' for g in groups))


@composite
def valid_ip_addresses(draw):
    """Generate valid IP addresses (IPv4 or IPv6)."""
    return draw(st.one_of(valid_ipv4_addresses(), valid_ipv6_addresses()))


class TestClassificationConsistency:
    """Property-based tests for classification consistency."""

    @given(valid_ip_addresses())
    def test_classification_results_consistent_with_json_definitions(self, ip_address):
        """
        Property 11: Classification Consistency
        For any IP address, classification results should be consistent with current JSON definitions.
        **Validates: Requirements 6.3, 6.4, 6.5**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"
            
            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            # Load the classification rules directly
            rules = config_manager.load_classifications()
            
            # Initialize classification module
            classifier = ClassificationModule(config_manager)
            
            # Perform classification
            results = classifier.classify_ip(ip_address)
            
            # Verify consistency with JSON definitions
            for result in results:
                rule_name = result["name"]
                assert rule_name in rules, f"Classification result '{rule_name}' should exist in JSON definitions"
                
                rule = rules[rule_name]
                
                # Verify all fields match the JSON definition
                assert result["ip_range"] == rule.ip_range, f"IP range should match JSON definition for {rule_name}"
                assert result["description"] == rule.description, f"Description should match JSON definition for {rule_name}"
                assert result["qualifies_for"] == rule.qualifies_for, f"Qualifies_for should match JSON definition for {rule_name}"
                assert result.get("rfc_reference") == rule.rfc_reference, f"RFC reference should match JSON definition for {rule_name}"

    @given(valid_ip_addresses())
    def test_classification_includes_valid_qualifies_for_modules(self, ip_address):
        """
        Property 11: Classification Consistency (Module Qualification)
        For any IP address classification, the qualifies_for field should contain valid module names.
        **Validates: Requirements 6.3, 6.4, 6.5**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"
            
            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            classifier = ClassificationModule(config_manager)
            results = classifier.classify_ip(ip_address)
            
            valid_modules = {"local_info", "internet_info", "netbox", "checkmk", 
                           "openitcockpit", "openvas", "infoblox"}
            
            for result in results:
                qualifies_for = result.get("qualifies_for", [])
                assert isinstance(qualifies_for, list), f"qualifies_for should be a list for {result['name']}"
                
                for module in qualifies_for:
                    assert module in valid_modules, f"Module '{module}' in qualifies_for should be valid for {result['name']}"

    @given(valid_ip_addresses())
    def test_classification_module_qualification_consistency(self, ip_address):
        """
        Property 11: Classification Consistency (Module Qualification Logic)
        For any IP address, the qualified modules should be consistent with classification results.
        **Validates: Requirements 6.3, 6.4, 6.5**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"
            
            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            classifier = ClassificationModule(config_manager)
            
            # Get classification results and qualified modules
            classifications = classifier.classify_ip(ip_address)
            qualified_modules = classifier.get_qualified_modules(classifications)
            
            # Collect all modules that should be qualified based on classifications
            expected_modules = set()
            for classification in classifications:
                expected_modules.update(classification.get("qualifies_for", []))
            
            # Verify consistency
            assert set(qualified_modules) == expected_modules, \
                f"Qualified modules {qualified_modules} should match expected modules {expected_modules}"

    @given(valid_ip_addresses())
    def test_classification_deterministic_behavior(self, ip_address):
        """
        Property 11: Classification Consistency (Deterministic Behavior)
        For any IP address, multiple classification calls should return identical results.
        **Validates: Requirements 6.3, 6.4, 6.5**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"
            
            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            classifier = ClassificationModule(config_manager)
            
            # Perform classification multiple times
            results1 = classifier.classify_ip(ip_address)
            results2 = classifier.classify_ip(ip_address)
            results3 = classifier.classify_ip(ip_address)
            
            # Results should be identical
            assert results1 == results2, "Classification results should be deterministic (call 1 vs 2)"
            assert results2 == results3, "Classification results should be deterministic (call 2 vs 3)"
            assert results1 == results3, "Classification results should be deterministic (call 1 vs 3)"

    @given(valid_ip_addresses())
    def test_classification_json_file_consistency_after_reload(self, ip_address):
        """
        Property 11: Classification Consistency (File Persistence)
        For any IP address, classification results should be consistent after JSON file reload.
        **Validates: Requirements 6.3, 6.4, 6.5**
        """
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"
            
            config_manager1 = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            classifier1 = ClassificationModule(config_manager1)
            results1 = classifier1.classify_ip(ip_address)
            
            # Create a new config manager that loads from the same files
            config_manager2 = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            classifier2 = ClassificationModule(config_manager2)
            results2 = classifier2.classify_ip(ip_address)
            
            # Results should be identical
            assert results1 == results2, "Classification results should be consistent after JSON file reload"