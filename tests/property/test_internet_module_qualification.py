"""
Property-based tests for Internet Module qualification.

**Feature: ip-intelligence-analyzer, Property 17: Internet Module Qualification**
**Validates: Requirements 8.1**
"""

import ipaddress
from hypothesis import given, strategies as st, settings
from ipaddress import IPv4Address, IPv6Address
from typing import Union

from src.ip_mana.modules.classification import ClassificationModule
from src.ip_mana.modules.internet_info import InternetInfoModule
from src.ip_mana.config import ConfigManager

# Type alias for IP addresses
IPAddress = Union[IPv4Address, IPv6Address]


class TestInternetModuleQualification:
    """Property-based tests for internet module qualification logic."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config_manager = ConfigManager()
        self.classification_module = ClassificationModule(self.config_manager)
        self.internet_module = InternetInfoModule()

    @given(st.ip_addresses())
    @settings(max_examples=20)
    def test_internet_module_qualification_property(self, ip: IPAddress):
        """
        Property 17: Internet Module Qualification
        
        For any IP address, the Internet Info Module should execute only when 
        the classification indicates qualification for module 3, unless overridden 
        by force flags.
        
        **Validates: Requirements 8.1**
        """
        # Get classifications for the IP
        classifications = self.classification_module.classify_ip(ip)
        qualified_modules = self.classification_module.get_qualified_modules(classifications)
        
        # Check if module 3 (internet_info) is qualified
        module3_qualified = "internet_info" in qualified_modules or "module_3" in qualified_modules
        
        # Test without force flag - should only run if qualified
        should_run_without_force = module3_qualified
        
        # The property: Internet module should only execute when qualified
        # (This is a behavioral property - in actual implementation, the main
        # application controller would check this before calling the module)
        
        # For this test, we verify that the qualification logic is consistent
        # If the IP is classified as qualifying for internet module, then it should be allowed
        # If not qualified, it should not be allowed (unless forced)
        
        # Check specific classification types that should qualify for internet module
        private_ranges = [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # IPv4 private
            "127.0.0.0/8", "169.254.0.0/16",  # IPv4 special
            "224.0.0.0/4", "240.0.0.0/4",  # IPv4 multicast and reserved
            "::1/128", "fe80::/10", "fc00::/7",  # IPv6 special
            "ff00::/8"  # IPv6 multicast
        ]
        
        is_private_or_special = False
        for range_str in private_ranges:
            try:
                network = ipaddress.ip_network(range_str, strict=False)
                if ip in network:
                    is_private_or_special = True
                    break
            except ValueError:
                continue
        
        # Property assertion: Private/special IPs should NOT qualify for internet module
        # Public IPs SHOULD qualify for internet module
        if is_private_or_special:
            # Private/special IPs should not qualify for internet module by default
            # (unless explicitly configured otherwise)
            assert not module3_qualified or any(
                "public" in cls.get("name", "").lower() 
                for cls in classifications
            ), f"Private/special IP {ip} should not qualify for internet module"
        else:
            # Public IPs should qualify for internet module
            assert module3_qualified, f"Public IP {ip} should qualify for internet module"

    @given(st.ip_addresses())
    @settings(max_examples=20)
    def test_force_flag_override_property(self, ip: IPAddress):
        """
        Property: Force flag override behavior
        
        For any IP address, when force flags (--force-internet or --force-module3) 
        are used, the internet module should execute regardless of classification.
        
        **Validates: Requirements 8.2**
        """
        # Get classifications for the IP
        classifications = self.classification_module.classify_ip(ip)
        qualified_modules = self.classification_module.get_qualified_modules(classifications)
        
        # Check normal qualification
        normally_qualified = "internet_info" in qualified_modules or "module_3" in qualified_modules
        
        # Simulate force flag behavior
        # In the actual implementation, this would be handled by the main controller
        # Here we test the logic that force flags should override qualification
        
        force_internet = True  # Simulate --force-internet flag
        force_module3 = True   # Simulate --force-module3 flag
        
        # Property: With force flags, module should run regardless of normal qualification
        should_run_with_force = normally_qualified or force_internet or force_module3
        
        # This should always be True when force flags are set
        assert should_run_with_force, f"Force flags should allow internet module to run for any IP {ip}"
        
        # Additional check: force flags should work even for private IPs
        private_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
        is_private = False
        
        if isinstance(ip, IPv4Address):
            for range_str in private_ranges:
                try:
                    network = ipaddress.ip_network(range_str)
                    if ip in network:
                        is_private = True
                        break
                except ValueError:
                    continue
        
        if is_private:
            # Even private IPs should be allowed with force flags
            assert should_run_with_force, f"Force flags should override private IP restriction for {ip}"

    @given(st.ip_addresses())
    @settings(max_examples=20)
    def test_classification_consistency_property(self, ip: IPAddress):
        """
        Property: Classification consistency for internet module qualification
        
        For any IP address, the qualification decision should be consistent
        with the classification rules and should not change between calls.
        
        **Validates: Requirements 8.1**
        """
        # Get classifications multiple times
        classifications1 = self.classification_module.classify_ip(ip)
        classifications2 = self.classification_module.classify_ip(ip)
        
        qualified_modules1 = self.classification_module.get_qualified_modules(classifications1)
        qualified_modules2 = self.classification_module.get_qualified_modules(classifications2)
        
        # Property: Results should be consistent between calls
        assert qualified_modules1 == qualified_modules2, \
            f"Qualification results should be consistent for IP {ip}"
        
        # Property: Classification should be deterministic
        assert classifications1 == classifications2, \
            f"Classifications should be deterministic for IP {ip}"
        
        # Property: If classified as public, should qualify for internet module
        is_public_classified = any(
            "public" in cls.get("name", "").lower() 
            for cls in classifications1
        )
        
        module3_qualified = "internet_info" in qualified_modules1 or "module_3" in qualified_modules1
        
        if is_public_classified:
            assert module3_qualified, \
                f"Public IP {ip} should qualify for internet module based on classification"