"""
Property-based tests for IP classification accuracy.

**Feature: ip-intelligence-analyzer, Property 10: Classification Accuracy**
**Validates: Requirements 6.1, 6.7**
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
    # Generate components for IPv4 address
    octets = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
    return ipaddress.IPv4Address('.'.join(map(str, octets)))


@composite
def valid_ipv6_addresses(draw):
    """Generate valid IPv6 addresses."""
    # Generate components for IPv6 address
    groups = [draw(st.integers(min_value=0, max_value=0xFFFF)) for _ in range(8)]
    return ipaddress.IPv6Address(':'.join(f'{g:x}' for g in groups))


@composite
def valid_ip_addresses(draw):
    """Generate valid IP addresses (IPv4 or IPv6)."""
    return draw(st.one_of(valid_ipv4_addresses(), valid_ipv6_addresses()))


@composite
def classification_rules(draw):
    """Generate valid classification rules."""
    name = draw(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='_-')))
    
    # Generate valid IP ranges
    ip_version = draw(st.integers(min_value=4, max_value=6))
    if ip_version == 4:
        base_ip = draw(valid_ipv4_addresses())
        prefix_len = draw(st.integers(min_value=8, max_value=32))
    else:
        base_ip = draw(valid_ipv6_addresses())
        prefix_len = draw(st.integers(min_value=16, max_value=128))
    
    ip_range = f"{base_ip}/{prefix_len}"
    
    description = draw(st.text(min_size=1, max_size=200))
    
    # Generate valid module names
    valid_modules = ["local_info", "internet_info", "netbox", "checkmk", "openitcockpit", "openvas", "infoblox"]
    qualifies_for = draw(st.lists(st.sampled_from(valid_modules), min_size=0, max_size=3, unique=True))
    
    rfc_reference = draw(st.one_of(st.none(), st.text(min_size=1, max_size=50)))
    
    return ClassificationRule(
        name=name,
        ip_range=ip_range,
        description=description,
        qualifies_for=qualifies_for,
        rfc_reference=rfc_reference
    )


class TestClassificationAccuracy:
    """Property-based tests for classification accuracy."""

    @given(valid_ip_addresses())
    def test_classification_returns_valid_results(self, ip_address):
        """
        Property 10: Classification Accuracy
        For any valid IP address, classification should return valid classification results.
        **Validates: Requirements 6.1, 6.7**
        """
        # Create temporary config manager with default rules
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"
            
            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            # Initialize classification module
            classifier = ClassificationModule(config_manager)
            
            # Perform classification
            results = classifier.classify_ip(ip_address)
            
            # Verify results are valid
            assert isinstance(results, list), "Classification results must be a list"
            assert len(results) >= 1, "At least one classification should be returned"
            
            for result in results:
                assert isinstance(result, dict), "Each classification result must be a dictionary"
                assert "name" in result, "Classification must have a name"
                assert "ip_range" in result, "Classification must have an ip_range"
                assert "description" in result, "Classification must have a description"
                assert "qualifies_for" in result, "Classification must have qualifies_for"
                
                # Verify the IP actually belongs to the classified range
                try:
                    network = ipaddress.ip_network(result["ip_range"], strict=False)
                    assert ip_address in network, f"IP {ip_address} should be in classified range {result['ip_range']}"
                except ValueError:
                    assert False, f"Invalid IP range in classification: {result['ip_range']}"

    @given(valid_ip_addresses())
    def test_classification_consistency_with_rfc_ranges(self, ip_address):
        """
        Property 10: Classification Accuracy (RFC Compliance)
        For any IP address, classifications should be consistent with RFC-defined ranges.
        **Validates: Requirements 6.1, 6.7**
        """
        # Create temporary config manager with default rules
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"
            
            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            classifier = ClassificationModule(config_manager)
            results = classifier.classify_ip(ip_address)
            
            # Check specific RFC compliance for known ranges
            if ip_address.version == 4:
                if ip_address in ipaddress.ip_network("10.0.0.0/8"):
                    assert any(r["name"] == "private_ipv4_10" for r in results), "10.x.x.x should be classified as private_ipv4_10"
                elif ip_address in ipaddress.ip_network("172.16.0.0/12"):
                    assert any(r["name"] == "private_ipv4_172" for r in results), "172.16-31.x.x should be classified as private_ipv4_172"
                elif ip_address in ipaddress.ip_network("192.168.0.0/16"):
                    assert any(r["name"] == "private_ipv4_192" for r in results), "192.168.x.x should be classified as private_ipv4_192"
                elif ip_address in ipaddress.ip_network("127.0.0.0/8"):
                    assert any(r["name"] == "localhost_ipv4" for r in results), "127.x.x.x should be classified as localhost_ipv4"
            else:  # IPv6
                if ip_address in ipaddress.ip_network("::1/128"):
                    assert any(r["name"] == "localhost_ipv6" for r in results), "::1 should be classified as localhost_ipv6"
                elif ip_address in ipaddress.ip_network("fc00::/7"):
                    assert any(r["name"] == "private_ipv6_unique_local" for r in results), "fc00::/7 should be classified as private_ipv6_unique_local"
                elif ip_address in ipaddress.ip_network("fe80::/10"):
                    assert any(r["name"] == "link_local_ipv6" for r in results), "fe80::/10 should be classified as link_local_ipv6"

    @given(classification_rules(), valid_ip_addresses())
    def test_custom_classification_accuracy(self, custom_rule, ip_address):
        """
        Property 10: Classification Accuracy (Custom Rules)
        For any custom classification rule and IP address, if the IP is in the rule's range,
        it should be correctly classified.
        **Validates: Requirements 6.1, 6.7**
        """
        # Skip if IP doesn't match the rule's IP version
        try:
            rule_network = ipaddress.ip_network(custom_rule.ip_range, strict=False)
            assume(ip_address.version == rule_network.version)
        except ValueError:
            assume(False)  # Skip invalid IP ranges
        
        # Create temporary config manager
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            classifications_path = Path(temp_dir) / "classifications.json"
            
            config_manager = ConfigManager(
                config_path=config_path,
                classifications_path=classifications_path
            )
            
            # Add the custom rule
            try:
                config_manager.add_classification(custom_rule)
            except ValueError:
                assume(False)  # Skip invalid rules
            
            classifier = ClassificationModule(config_manager)
            results = classifier.classify_ip(ip_address)
            
            # Check if IP is in the custom rule's range
            if ip_address in rule_network:
                # Should find the custom classification (unless it's a broad public range)
                if custom_rule.name not in ["public_ipv4", "public_ipv6"]:
                    assert any(r["name"] == custom_rule.name for r in results), \
                        f"IP {ip_address} in range {custom_rule.ip_range} should be classified as {custom_rule.name}"