"""
Property-based tests for Local Network Analysis Completeness.

Feature: ip-intelligence-analyzer, Property 13: Local Network Analysis Completeness
Validates: Requirements 7.1, 7.2, 7.3, 7.8, 7.9, 7.10
"""

from hypothesis import given, strategies as st, settings
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import patch, MagicMock

from src.ip_mana.modules.local_info import LocalInfoModule, LocalInfoResult


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


class TestLocalNetworkAnalysisCompleteness:
    """Test Property 13: Local Network Analysis Completeness."""

    @given(ip_addresses())
    @settings(max_examples=100, deadline=None)  # Disable deadline for complex tests
    def test_local_analysis_completeness(self, ip):
        """
        Property 13: Local Network Analysis Completeness

        For any IP address processed by the Local Info Module, the module should
        attempt all configured local analysis methods (subnet check, ping, MAC discovery,
        nmap scans) and return structured results for each.

        **Validates: Requirements 7.1, 7.2, 7.3, 7.8, 7.9, 7.10**
        """
        # Mock external dependencies to ensure consistent testing
        with patch('src.ip_mana.modules.local_info.netifaces') as mock_netifaces, \
                patch('src.ip_mana.modules.local_info.subprocess') as mock_subprocess, \
                patch('src.ip_mana.modules.local_info.nmap.PortScanner') as mock_nmap, \
                patch('src.ip_mana.modules.local_info.socket') as mock_socket:

            # Setup mocks for consistent behavior
            self._setup_mocks(
                mock_netifaces,
                mock_subprocess,
                mock_nmap,
                mock_socket,
                ip)

            # Create module and perform analysis
            module = LocalInfoModule()
            result = module.analyze(ip)

            # Verify result structure and completeness
            assert isinstance(
                result, LocalInfoResult), "Result must be LocalInfoResult instance"

            # Verify all required fields are present (Requirements 7.1, 7.2, 7.3)
            assert hasattr(
                result, 'is_local_subnet'), "Must check local subnet membership"
            assert hasattr(result, 'reachable'), "Must test reachability"
            assert hasattr(result, 'mac_address'), "Must attempt MAC discovery"

            # Verify nmap results structure (Requirements 7.8, 7.9, 7.10)
            assert hasattr(result, 'nmap_results'), "Must perform nmap scanning"
            assert hasattr(result.nmap_results, 'host_up'), "Must check if host is up"
            assert hasattr(
                result.nmap_results, 'os_detection'), "Must attempt OS detection"
            assert hasattr(
                result.nmap_results, 'open_ports'), "Must scan for open ports"
            assert hasattr(result.nmap_results, 'services'), "Must detect services"

            # Verify additional analysis components
            assert hasattr(result, 'ssl_results'), "Must analyze SSL services"
            assert hasattr(result, 'traceroute_results'), "Must perform traceroute"
            assert hasattr(result, 'reverse_dns'), "Must attempt reverse DNS"

            # Verify data types are correct
            assert isinstance(result.is_local_subnet,
                              bool), "Subnet check must return boolean"
            assert isinstance(
                result.reachable, bool), "Reachability must return boolean"
            assert isinstance(result.ssl_results, list), "SSL results must be list"
            assert isinstance(result.traceroute_results,
                              list), "Traceroute results must be list"

    @given(ip_addresses())
    @settings(max_examples=50, deadline=None)
    def test_analysis_methods_attempted(self, ip):
        """
        Verify that all analysis methods are attempted regardless of IP address.

        This ensures the module attempts subnet checking, ping testing, MAC discovery,
        and nmap scanning for any valid IP address input.
        """
        with patch('src.ip_mana.modules.local_info.netifaces') as mock_netifaces, \
                patch('src.ip_mana.modules.local_info.subprocess') as mock_subprocess, \
                patch('src.ip_mana.modules.local_info.nmap.PortScanner') as mock_nmap, \
                patch('src.ip_mana.modules.local_info.socket') as mock_socket:

            self._setup_mocks(
                mock_netifaces,
                mock_subprocess,
                mock_nmap,
                mock_socket,
                ip)

            module = LocalInfoModule()
            module.analyze(ip)

            # Verify that netifaces was called for subnet checking (Requirement 7.1)
            mock_netifaces.interfaces.assert_called()

            # Verify that subprocess was called for ping testing (Requirement 7.2)
            mock_subprocess.run.assert_called()

            # Verify that nmap scanner was used (Requirements 7.8, 7.9, 7.10)
            mock_nmap.assert_called()

    def _setup_mocks(self, mock_netifaces, mock_subprocess, mock_nmap, mock_socket, ip):
        """Setup consistent mocks for testing."""
        # Mock netifaces for subnet checking
        mock_netifaces.interfaces.return_value = ['eth0', 'lo']
        mock_netifaces.ifaddresses.return_value = {
            2: [{'addr': '192.168.1.100', 'netmask': '255.255.255.0'}]  # AF_INET
        }
        mock_netifaces.AF_INET = 2
        mock_netifaces.AF_INET6 = 10
        mock_netifaces.gateways.return_value = {'default': {}}

        # Mock subprocess for ping and other system calls
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "64 bytes from 192.168.1.1: time=1.23 ms"
        mock_result.stderr = ""
        mock_subprocess.run.return_value = mock_result
        mock_subprocess.TimeoutExpired = Exception  # Mock the exception class

        # Mock socket for reverse DNS
        mock_socket.gethostbyaddr.return_value = ('example.com', [], [str(ip)])

        # Mock nmap scanner
        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = [str(ip)]

        # Create a proper mock for the host object
        mock_host = MagicMock()
        mock_host.all_protocols.return_value = ['tcp']
        mock_host.__getitem__.return_value = {
            80: {'state': 'open', 'name': 'http', 'version': '', 'product': ''},
            443: {'state': 'open', 'name': 'https', 'version': '', 'product': ''}
        }

        # Set up the scanner to return the mock host
        mock_scanner.__getitem__.return_value = mock_host
        mock_nmap.return_value = mock_scanner


class TestLocalAnalysisErrorHandling:
    """Test error handling in local network analysis."""

    @given(ip_addresses())
    @settings(max_examples=25, deadline=None)
    def test_graceful_error_handling(self, ip):
        """
        Verify that analysis continues even when individual components fail.

        The module should handle network errors, permission issues, and missing
        tools gracefully without terminating the entire analysis.
        """
        with patch('src.ip_mana.modules.local_info.netifaces') as mock_netifaces, \
                patch('src.ip_mana.modules.local_info.subprocess') as mock_subprocess, \
                patch('src.ip_mana.modules.local_info.nmap.PortScanner') as mock_nmap, \
                patch('src.ip_mana.modules.local_info.socket') as mock_socket:

            # Setup mocks to simulate failures during analysis, not initialization
            mock_netifaces.interfaces.side_effect = Exception("Network interface error")

            # Mock subprocess with proper exception handling
            mock_subprocess.run.side_effect = Exception("Subprocess error")
            mock_subprocess.TimeoutExpired = Exception  # Mock the exception class

            # Mock socket errors
            mock_socket.gethostbyaddr.side_effect = Exception("DNS error")

            # Allow nmap initialization to succeed, but make scan fail
            mock_scanner = MagicMock()
            mock_scanner.scan.side_effect = Exception("Nmap scan error")
            mock_scanner.all_hosts.return_value = []  # No hosts found
            mock_nmap.return_value = mock_scanner

            module = LocalInfoModule()
            result = module.analyze(ip)

            # Analysis should complete despite errors
            assert isinstance(result, LocalInfoResult)

            # Failed components should have safe default values
            assert isinstance(result.is_local_subnet, bool)
            assert isinstance(result.reachable, bool)
            assert result.mac_address is None  # Should be None when discovery fails
            assert isinstance(result.nmap_results.open_ports, list)
            assert isinstance(result.ssl_results, list)
            assert isinstance(result.traceroute_results, list)
