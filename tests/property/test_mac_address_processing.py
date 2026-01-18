"""
Property-based tests for MAC Address Processing.

Feature: ip-intelligence-analyzer, Property 14: MAC Address Processing
Validates: Requirements 7.4, 7.5
"""

from hypothesis import given, strategies as st, settings
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import patch, MagicMock

from src.ip_mana.modules.local_info import LocalInfoModule, MACAddress


# Strategy for generating valid IP addresses
@st.composite
def ip_addresses(draw):
    """Generate valid IPv4 and IPv6 addresses."""
    ip_type = draw(st.sampled_from(['ipv4', 'ipv6']))

    if ip_type == 'ipv4':
        # Generate IPv4 addresses (avoid reserved ranges for testing)
        octets = draw(st.lists(st.integers(1, 254), min_size=4, max_size=4))
        ip_str = '.'.join(map(str, octets))
        return IPv4Address(ip_str)
    else:
        # Generate IPv6 addresses
        parts = draw(st.lists(st.integers(0, 65535), min_size=8, max_size=8))
        ip_str = ':'.join(f'{part:x}' for part in parts)
        return IPv6Address(ip_str)


# Strategy for generating valid MAC addresses
@st.composite
def mac_addresses(draw):
    """Generate valid MAC addresses."""
    # Generate 6 octets for MAC address
    octets = draw(st.lists(st.integers(0, 255), min_size=6, max_size=6))
    mac_str = ':'.join(f'{octet:02x}' for octet in octets)
    return mac_str


class TestMACAddressProcessing:
    """Test Property 14: MAC Address Processing."""

    @given(ip_addresses(), mac_addresses())
    @settings(max_examples=100)
    def test_mac_vendor_decoding(self, ip, mac_address):
        """
        Property 14: MAC Address Processing

        For any discovered MAC address, the system should decode the vendor portion
        and correctly classify whether it represents a network interface or
        router/gateway based on network topology.

        **Validates: Requirements 7.4, 7.5**
        """
        with patch('src.ip_mana.modules.local_info.subprocess') as mock_subprocess, \
                patch('src.ip_mana.modules.local_info.netifaces') as mock_netifaces:

            # Setup mocks to return the test MAC address
            self._setup_mac_mocks(mock_subprocess, mock_netifaces, ip, mac_address)

            module = LocalInfoModule()
            result = module.get_mac_address(ip)

            if result is not None:
                # Verify MAC address structure (Requirement 7.4)
                assert isinstance(
                    result, MACAddress), "Result must be MACAddress instance"
                assert isinstance(result.address, str), "MAC address must be string"
                assert len(result.address.split(':')
                           ) == 6, "MAC address must have 6 octets"

                # Verify vendor decoding attempt (Requirement 7.4)
                assert hasattr(result, 'vendor'), "Must attempt vendor decoding"
                # Vendor can be None if not found, but attribute must exist

                # Verify gateway classification (Requirement 7.5)
                assert isinstance(
                    result.is_gateway, bool), "Gateway classification must be boolean"

    @given(mac_addresses())
    @settings(max_examples=100)
    def test_mac_vendor_consistency(self, mac_address):
        """
        Verify that vendor decoding is consistent for the same MAC address.

        The same MAC address should always produce the same vendor result.
        """
        module = LocalInfoModule()

        # Test vendor lookup directly
        vendor1 = module._get_mac_vendor(mac_address)
        vendor2 = module._get_mac_vendor(mac_address)

        # Results should be consistent
        assert vendor1 == vendor2, "Vendor lookup must be consistent"

        # Vendor should be string or None
        assert vendor1 is None or isinstance(
            vendor1, str), "Vendor must be string or None"

    @given(ip_addresses())
    @settings(max_examples=100)
    def test_gateway_classification_logic(self, ip):
        """
        Verify that gateway classification logic works correctly.

        The system should correctly identify when a MAC address belongs to
        a gateway/router based on network topology information.
        """
        with patch('src.ip_mana.modules.local_info.netifaces') as mock_netifaces:

            # Test case 1: IP is the default gateway
            mock_netifaces.gateways.return_value = {
                'default': {2: (str(ip), 'eth0')}  # AF_INET
            }

            module = LocalInfoModule()
            is_gateway = module._is_gateway_mac(ip, "00:11:22:33:44:55")

            assert isinstance(is_gateway, bool), "Gateway check must return boolean"
            assert is_gateway, "Should identify gateway IP correctly"

            # Test case 2: IP is not the default gateway
            mock_netifaces.gateways.return_value = {
                'default': {2: ("192.168.1.1", 'eth0')}  # Different IP
            }

            is_gateway = module._is_gateway_mac(ip, "00:11:22:33:44:55")
            assert is_gateway is False, "Should not identify non-gateway IP as gateway"

    @given(mac_addresses())
    @settings(max_examples=50)
    def test_mac_address_normalization(self, mac_address):
        """
        Verify that MAC addresses are properly normalized to consistent format.

        MAC addresses should be converted to lowercase with colon separators.
        """
        module = LocalInfoModule()

        # Test with different formats
        mac_variants = [
            mac_address.upper(),  # Uppercase
            mac_address.lower(),  # Lowercase
            mac_address.replace(':', '-'),  # Dash separators
        ]

        for mac_variant in mac_variants:
            with patch('src.ip_mana.modules.local_info.subprocess') as mock_subprocess:
                # Mock ARP output with the variant
                mock_result = MagicMock()
                mock_result.returncode = 0
                mock_result.stdout = f"192.168.1.1 ether {mac_variant} C eth0"
                mock_subprocess.run.return_value = mock_result

                result_mac = module._get_mac_from_arp(IPv4Address('192.168.1.1'))

                if result_mac:
                    # Should be normalized to lowercase with colons
                    assert ':' in result_mac, "MAC should use colon separators"
                    # Check that alphabetic characters are lowercase (digits don't have
                    # case)
                    for char in result_mac:
                        if char.isalpha():
                            assert char.islower(
                            ), f"Alphabetic characters should be lowercase: {result_mac}"

    def _setup_mac_mocks(self, mock_subprocess, mock_netifaces, ip, mac_address):
        """Setup mocks for MAC address testing."""
        # Mock ARP table lookup
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = f"{ip} ether {mac_address} C eth0"
        mock_result.stderr = ""
        mock_subprocess.run.return_value = mock_result

        # Mock netifaces for gateway checking
        mock_netifaces.gateways.return_value = {
            'default': {2: ("192.168.1.1", 'eth0')}
        }


class TestMACAddressErrorHandling:
    """Test error handling in MAC address processing."""

    @given(ip_addresses())
    @settings(max_examples=50)
    def test_mac_discovery_failure_handling(self, ip):
        """
        Verify graceful handling when MAC address discovery fails.

        The system should handle ARP lookup failures, permission issues,
        and missing network tools without crashing.
        """
        with patch('src.ip_mana.modules.local_info.subprocess') as mock_subprocess, \
                patch('src.ip_mana.modules.local_info.netifaces') as mock_netifaces:

            # Test case 1: ARP command fails
            mock_subprocess.run.side_effect = Exception("ARP command failed")
            mock_netifaces.gateways.return_value = {'default': {}}

            module = LocalInfoModule()
            result = module.get_mac_address(ip)

            # Should return None gracefully
            assert result is None, "Should return None when MAC discovery fails"

            # Test case 2: ARP returns no MAC
            mock_subprocess.run.side_effect = None
            mock_result = MagicMock()
            mock_result.returncode = 1  # Command failed
            mock_result.stdout = "No entry found"
            mock_subprocess.run.return_value = mock_result

            result = module.get_mac_address(ip)
            assert result is None, "Should return None when no MAC found"

    @given(mac_addresses())
    @settings(max_examples=50)
    def test_vendor_lookup_error_handling(self, mac_address):
        """
        Verify that vendor lookup handles malformed MAC addresses gracefully.
        """
        module = LocalInfoModule()

        # Test with malformed MAC addresses
        malformed_macs = [
            "invalid",
            "00:11:22",  # Too short
            "00:11:22:33:44:55:66:77",  # Too long
            "",  # Empty
        ]

        for bad_mac in malformed_macs:
            vendor = module._get_mac_vendor(bad_mac)
            # Should not crash and return None or string
            assert vendor is None or isinstance(
                vendor, str), f"Should handle malformed MAC: {bad_mac}"
