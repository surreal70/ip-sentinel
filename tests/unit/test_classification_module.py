"""
Unit tests for IP Classification Module.

Tests specific RFC ranges, edge cases, and custom classification rule handling.
Requirements: 6.1, 6.7
"""

import ipaddress
import tempfile
from pathlib import Path
import pytest

from src.ip_mana.config import ConfigManager, ClassificationRule
from src.ip_mana.modules.classification import ClassificationModule


class TestClassificationModule:
    """Unit tests for the ClassificationModule class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = Path(self.temp_dir.name) / "config.json"
        self.classifications_path = Path(self.temp_dir.name) / "classifications.json"
        
        self.config_manager = ConfigManager(
            config_path=self.config_path,
            classifications_path=self.classifications_path
        )
        self.classifier = ClassificationModule(self.config_manager)

    def teardown_method(self):
        """Clean up test fixtures."""
        self.temp_dir.cleanup()

    def test_classify_private_ipv4_class_a(self):
        """Test classification of private IPv4 Class A addresses (10.x.x.x)."""
        # Test specific addresses in 10.0.0.0/8 range
        test_ips = [
            "10.0.0.1",
            "10.1.1.1", 
            "10.255.255.254"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as private_ipv4_10
            assert len(results) >= 1, f"IP {ip_str} should have at least one classification"
            assert any(r["name"] == "private_ipv4_10" for r in results), \
                f"IP {ip_str} should be classified as private_ipv4_10"
            
            # Verify the classification details
            private_classification = next(r for r in results if r["name"] == "private_ipv4_10")
            assert private_classification["ip_range"] == "10.0.0.0/8"
            assert "local_info" in private_classification["qualifies_for"]
            assert private_classification["rfc_reference"] == "RFC 1918"

    def test_classify_private_ipv4_class_b(self):
        """Test classification of private IPv4 Class B addresses (172.16-31.x.x)."""
        # Test specific addresses in 172.16.0.0/12 range
        test_ips = [
            "172.16.0.1",
            "172.20.1.1",
            "172.31.255.254"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as private_ipv4_172
            assert any(r["name"] == "private_ipv4_172" for r in results), \
                f"IP {ip_str} should be classified as private_ipv4_172"

    def test_classify_private_ipv4_class_c(self):
        """Test classification of private IPv4 Class C addresses (192.168.x.x)."""
        # Test specific addresses in 192.168.0.0/16 range
        test_ips = [
            "192.168.0.1",
            "192.168.1.1",
            "192.168.143.55",
            "192.168.143.2",
            "192.168.255.254"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as private_ipv4_192
            assert any(r["name"] == "private_ipv4_192" for r in results), \
                f"IP {ip_str} should be classified as private_ipv4_192"

    def test_classify_localhost_ipv4(self):
        """Test classification of IPv4 localhost addresses (127.x.x.x)."""
        # Test specific addresses in 127.0.0.0/8 range
        test_ips = [
            "127.0.0.1",
            "127.1.1.1",
            "127.255.255.254"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as localhost_ipv4
            assert any(r["name"] == "localhost_ipv4" for r in results), \
                f"IP {ip_str} should be classified as localhost_ipv4"
            
            # Verify the classification details
            localhost_classification = next(r for r in results if r["name"] == "localhost_ipv4")
            assert localhost_classification["ip_range"] == "127.0.0.0/8"
            assert "local_info" in localhost_classification["qualifies_for"]
            assert localhost_classification["rfc_reference"] == "RFC 1122"

    def test_classify_link_local_ipv4(self):
        """Test classification of IPv4 link-local addresses (169.254.x.x)."""
        # Test specific addresses in 169.254.0.0/16 range
        test_ips = [
            "169.254.0.1",
            "169.254.1.1",
            "169.254.255.254"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as link_local_ipv4
            assert any(r["name"] == "link_local_ipv4" for r in results), \
                f"IP {ip_str} should be classified as link_local_ipv4"

    def test_classify_multicast_ipv4(self):
        """Test classification of IPv4 multicast addresses (224-239.x.x.x)."""
        # Test specific addresses in 224.0.0.0/4 range
        test_ips = [
            "224.0.0.1",
            "230.1.1.1",
            "239.255.255.254"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as multicast_ipv4
            assert any(r["name"] == "multicast_ipv4" for r in results), \
                f"IP {ip_str} should be classified as multicast_ipv4"
            
            # Multicast addresses should not qualify for any modules
            multicast_classification = next(r for r in results if r["name"] == "multicast_ipv4")
            assert multicast_classification["qualifies_for"] == [], \
                "Multicast addresses should not qualify for any modules"

    def test_classify_broadcast_ipv4(self):
        """Test classification of IPv4 broadcast address (255.255.255.255)."""
        ip = ipaddress.ip_address("255.255.255.255")
        results = self.classifier.classify_ip(ip)
        
        # Should be classified as broadcast_ipv4
        assert any(r["name"] == "broadcast_ipv4" for r in results), \
            "255.255.255.255 should be classified as broadcast_ipv4"

    def test_classify_localhost_ipv6(self):
        """Test classification of IPv6 localhost address (::1)."""
        ip = ipaddress.ip_address("::1")
        results = self.classifier.classify_ip(ip)
        
        # Should be classified as localhost_ipv6
        assert any(r["name"] == "localhost_ipv6" for r in results), \
            "::1 should be classified as localhost_ipv6"
        
        # Verify the classification details
        localhost_classification = next(r for r in results if r["name"] == "localhost_ipv6")
        assert localhost_classification["ip_range"] == "::1/128"
        assert "local_info" in localhost_classification["qualifies_for"]
        assert localhost_classification["rfc_reference"] == "RFC 4291"

    def test_classify_private_ipv6_unique_local(self):
        """Test classification of IPv6 unique local addresses (fc00::/7)."""
        # Test specific addresses in fc00::/7 range
        test_ips = [
            "fc00::1",
            "fd00::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as private_ipv6_unique_local
            assert any(r["name"] == "private_ipv6_unique_local" for r in results), \
                f"IP {ip_str} should be classified as private_ipv6_unique_local"

    def test_classify_link_local_ipv6(self):
        """Test classification of IPv6 link-local addresses (fe80::/10)."""
        # Test specific addresses in fe80::/10 range
        test_ips = [
            "fe80::1",
            "fe80::dead:beef",
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:fffe"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as link_local_ipv6
            assert any(r["name"] == "link_local_ipv6" for r in results), \
                f"IP {ip_str} should be classified as link_local_ipv6"

    def test_classify_multicast_ipv6(self):
        """Test classification of IPv6 multicast addresses (ff00::/8)."""
        # Test specific addresses in ff00::/8 range
        test_ips = [
            "ff00::1",
            "ff02::1",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as multicast_ipv6
            assert any(r["name"] == "multicast_ipv6" for r in results), \
                f"IP {ip_str} should be classified as multicast_ipv6"
            
            # Multicast addresses should not qualify for any modules
            multicast_classification = next(r for r in results if r["name"] == "multicast_ipv6")
            assert multicast_classification["qualifies_for"] == [], \
                "IPv6 multicast addresses should not qualify for any modules"

    def test_classify_public_ipv4_fallback(self):
        """Test classification of public IPv4 addresses that don't match specific ranges."""
        # Test public IPv4 addresses that should fall back to public_ipv4
        test_ips = [
            "8.8.8.8",      # Google DNS
            "1.1.1.1",      # Cloudflare DNS
            "208.67.222.222" # OpenDNS
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as public_ipv4 (fallback)
            assert any(r["name"] == "public_ipv4" for r in results), \
                f"Public IP {ip_str} should be classified as public_ipv4"
            
            # Public IPs should qualify for both local_info and internet_info
            public_classification = next(r for r in results if r["name"] == "public_ipv4")
            assert "local_info" in public_classification["qualifies_for"]
            assert "internet_info" in public_classification["qualifies_for"]

    def test_classify_public_ipv6_fallback(self):
        """Test classification of public IPv6 addresses that don't match specific ranges."""
        # Test public IPv6 addresses that should fall back to public_ipv6
        test_ips = [
            "2001:4860:4860::8888",  # Google DNS
            "2606:4700:4700::1111"   # Cloudflare DNS
        ]
        
        for ip_str in test_ips:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            # Should be classified as public_ipv6 (fallback)
            assert any(r["name"] == "public_ipv6" for r in results), \
                f"Public IPv6 {ip_str} should be classified as public_ipv6"

    def test_edge_case_ipv4_boundaries(self):
        """Test edge cases at IPv4 range boundaries."""
        # Test boundary addresses
        boundary_tests = [
            ("9.255.255.255", "public_ipv4"),    # Just before 10.0.0.0/8
            ("10.0.0.0", "private_ipv4_10"),     # Start of 10.0.0.0/8
            ("10.255.255.255", "private_ipv4_10"), # End of 10.0.0.0/8
            ("11.0.0.0", "public_ipv4"),         # Just after 10.0.0.0/8
            ("172.15.255.255", "public_ipv4"),   # Just before 172.16.0.0/12
            ("172.16.0.0", "private_ipv4_172"),  # Start of 172.16.0.0/12
            ("172.31.255.255", "private_ipv4_172"), # End of 172.16.0.0/12
            ("172.32.0.0", "public_ipv4"),       # Just after 172.16.0.0/12
            ("192.167.255.255", "public_ipv4"),  # Just before 192.168.0.0/16
            ("192.168.0.0", "private_ipv4_192"), # Start of 192.168.0.0/16
            ("192.168.255.255", "private_ipv4_192"), # End of 192.168.0.0/16
            ("192.169.0.0", "public_ipv4"),      # Just after 192.168.0.0/16
        ]
        
        for ip_str, expected_classification in boundary_tests:
            ip = ipaddress.ip_address(ip_str)
            results = self.classifier.classify_ip(ip)
            
            assert any(r["name"] == expected_classification for r in results), \
                f"Boundary IP {ip_str} should be classified as {expected_classification}"

    def test_custom_classification_rule_handling(self):
        """Test handling of custom classification rules."""
        # Create a custom classification rule
        custom_rule = ClassificationRule(
            name="test_custom_range",
            ip_range="203.0.113.0/24",  # RFC 5737 test range
            description="Test custom classification range",
            qualifies_for=["internet_info"],
            rfc_reference="RFC 5737"
        )
        
        # Add the custom rule
        self.config_manager.add_classification(custom_rule)
        
        # Test IP in the custom range
        ip = ipaddress.ip_address("203.0.113.100")
        results = self.classifier.classify_ip(ip)
        
        # Should be classified with the custom rule
        assert any(r["name"] == "test_custom_range" for r in results), \
            "IP in custom range should be classified with custom rule"
        
        # Verify custom rule details
        custom_classification = next(r for r in results if r["name"] == "test_custom_range")
        assert custom_classification["ip_range"] == "203.0.113.0/24"
        assert custom_classification["description"] == "Test custom classification range"
        assert custom_classification["qualifies_for"] == ["internet_info"]
        assert custom_classification["rfc_reference"] == "RFC 5737"

    def test_overlapping_classification_rules(self):
        """Test behavior with overlapping classification rules."""
        # Create overlapping custom rules
        broad_rule = ClassificationRule(
            name="broad_test_range",
            ip_range="198.51.100.0/23",  # Covers .100.0/24 and .101.0/24
            description="Broad test range",
            qualifies_for=["local_info"],
            rfc_reference="Test"
        )
        
        narrow_rule = ClassificationRule(
            name="narrow_test_range", 
            ip_range="198.51.100.0/24",  # Subset of the broad range
            description="Narrow test range",
            qualifies_for=["internet_info"],
            rfc_reference="Test"
        )
        
        # Add both rules
        self.config_manager.add_classification(broad_rule)
        self.config_manager.add_classification(narrow_rule)
        
        # Test IP that matches both ranges
        ip = ipaddress.ip_address("198.51.100.50")
        results = self.classifier.classify_ip(ip)
        
        # Should match both rules since IP is in both ranges
        assert any(r["name"] == "narrow_test_range" for r in results), \
            "IP should match the narrow classification rule"
        
        assert any(r["name"] == "broad_test_range" for r in results), \
            "IP should also match the broad classification rule"
        
        # Test IP that only matches the broad range
        ip_broad_only = ipaddress.ip_address("198.51.101.50")  # In /23 but not in /24
        results_broad = self.classifier.classify_ip(ip_broad_only)
        
        # Should only match the broad rule
        assert any(r["name"] == "broad_test_range" for r in results_broad), \
            "IP should match the broad classification rule"
        
        assert not any(r["name"] == "narrow_test_range" for r in results_broad), \
            "IP should not match the narrow rule when outside its range"

    def test_get_qualified_modules(self):
        """Test module qualification determination."""
        # Test with private IP (should qualify for local_info only)
        private_ip = ipaddress.ip_address("192.168.1.1")
        private_classifications = self.classifier.classify_ip(private_ip)
        private_modules = self.classifier.get_qualified_modules(private_classifications)
        
        assert "local_info" in private_modules, "Private IP should qualify for local_info"
        assert "internet_info" not in private_modules, "Private IP should not qualify for internet_info"
        
        # Test with public IP (should qualify for both local_info and internet_info)
        public_ip = ipaddress.ip_address("8.8.8.8")
        public_classifications = self.classifier.classify_ip(public_ip)
        public_modules = self.classifier.get_qualified_modules(public_classifications)
        
        assert "local_info" in public_modules, "Public IP should qualify for local_info"
        assert "internet_info" in public_modules, "Public IP should qualify for internet_info"
        
        # Test with multicast IP (should qualify for no modules)
        multicast_ip = ipaddress.ip_address("224.0.0.1")
        multicast_classifications = self.classifier.classify_ip(multicast_ip)
        multicast_modules = self.classifier.get_qualified_modules(multicast_classifications)
        
        assert len(multicast_modules) == 0, "Multicast IP should not qualify for any modules"

    def test_create_default_classifications(self):
        """Test creation of default RFC-compliant classifications."""
        default_rules = self.classifier.create_default_classifications()
        
        # Verify all expected default rules exist
        expected_rules = [
            "private_ipv4_10", "private_ipv4_172", "private_ipv4_192",
            "localhost_ipv4", "link_local_ipv4", "multicast_ipv4", "broadcast_ipv4",
            "private_ipv6_unique_local", "localhost_ipv6", "link_local_ipv6", "multicast_ipv6",
            "public_ipv4", "public_ipv6"
        ]
        
        for rule_name in expected_rules:
            assert rule_name in default_rules, f"Default rule '{rule_name}' should exist"
            
            rule = default_rules[rule_name]
            assert isinstance(rule, ClassificationRule), f"Rule '{rule_name}' should be ClassificationRule instance"
            assert rule.name == rule_name, f"Rule name should match key"
            assert rule.ip_range, f"Rule '{rule_name}' should have ip_range"
            assert rule.description, f"Rule '{rule_name}' should have description"
            assert isinstance(rule.qualifies_for, list), f"Rule '{rule_name}' qualifies_for should be list"

    def test_invalid_ip_range_handling(self):
        """Test handling of invalid IP ranges in classification rules."""
        # Create a rule with invalid IP range
        invalid_rule = ClassificationRule(
            name="invalid_range",
            ip_range="invalid.ip.range/24",
            description="Invalid range test",
            qualifies_for=["local_info"],
            rfc_reference=None
        )
        
        # Adding invalid rule should raise ValueError
        with pytest.raises(ValueError, match="Invalid IP range format"):
            self.config_manager.add_classification(invalid_rule)

    def test_classification_with_no_config_manager(self):
        """Test classification module behavior without explicit config manager."""
        # Create classifier without config manager (should use default)
        classifier = ClassificationModule()
        
        # Should still work with default config
        ip = ipaddress.ip_address("192.168.1.1")
        results = classifier.classify_ip(ip)
        
        assert len(results) >= 1, "Classification should work with default config manager"
        assert any(r["name"] == "private_ipv4_192" for r in results), \
            "Should classify 192.168.1.1 as private_ipv4_192 with default config"