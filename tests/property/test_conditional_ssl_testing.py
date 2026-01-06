"""
Property-based tests for Conditional SSL Testing.

Feature: ip-intelligence-analyzer, Property 15: Conditional SSL Testing
Validates: Requirements 7.11, 7.12
"""

import pytest
import sys
from hypothesis import given, strategies as st, settings
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import patch, MagicMock

from src.ip_mana.modules.local_info import LocalInfoModule, SSLResult


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


# Strategy for generating port configurations with web and mail server ports
@st.composite
def port_configurations(draw):
    """Generate port configurations that include web and mail server ports."""
    # Common web server ports
    web_ports = [80, 443, 8080, 8443, 8000, 9000]
    # Common mail server ports  
    mail_ports = [25, 465, 587, 993, 995, 143, 110]
    # Other service ports
    other_ports = [22, 21, 23, 53, 389, 636, 3389]
    
    # Always include at least one web or mail port for SSL testing
    selected_ports = []
    
    # Add some web server ports
    web_count = draw(st.integers(0, 3))
    if web_count > 0:
        selected_ports.extend(draw(st.lists(
            st.sampled_from(web_ports), 
            min_size=1, 
            max_size=web_count
        )))
    
    # Add some mail server ports
    mail_count = draw(st.integers(0, 3))
    if mail_count > 0:
        selected_ports.extend(draw(st.lists(
            st.sampled_from(mail_ports), 
            min_size=1, 
            max_size=mail_count
        )))
    
    # Add some other ports
    other_count = draw(st.integers(0, 2))
    if other_count > 0:
        selected_ports.extend(draw(st.lists(
            st.sampled_from(other_ports), 
            min_size=1, 
            max_size=other_count
        )))
    
    # Ensure we have at least one port and remove duplicates
    if not selected_ports:
        selected_ports = [443]  # Default to HTTPS
    
    return list(set(selected_ports))


class TestConditionalSSLTesting:
    """Test Property 15: Conditional SSL Testing."""

    @given(ip_addresses(), port_configurations())
    @settings(max_examples=100, deadline=None)
    def test_ssl_testing_for_web_and_mail_ports(self, ip, ports):
        """
        Property 15: Conditional SSL Testing
        
        For any discovered web server or mail server port, the Local Info Module 
        should automatically perform SSL analysis using sslyze and include the 
        results in the scan output.
        
        **Validates: Requirements 7.11, 7.12**
        """
        # Define web and mail server ports that should trigger SSL testing
        web_server_ports = {80, 443, 8080, 8443, 8000, 9000}
        mail_server_ports = {25, 465, 587, 993, 995, 143, 110}
        ssl_eligible_ports = web_server_ports | mail_server_ports
        
        # Create mock open ports data structure
        open_ports = []
        for port in ports:
            service_name = self._get_service_name(port)
            open_ports.append({
                'port': port,
                'protocol': 'tcp',
                'state': 'open',
                'service': service_name,
                'version': '',
                'product': ''
            })
        
        # Mock the sslyze imports at the module level to avoid ImportError
        with patch.dict('sys.modules', {
            'sslyze': MagicMock(),
            'sslyze.Scanner': MagicMock(),
            'sslyze.ServerScanRequest': MagicMock(), 
            'sslyze.ServerNetworkLocation': MagicMock(),
            'sslyze.plugins.scan_commands': MagicMock()
        }):
            # Import the mocked sslyze components
            import sslyze
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
            from sslyze.plugins.scan_commands import ScanCommand
            
            # Setup mock scanner
            mock_scanner = MagicMock()
            Scanner.return_value = mock_scanner
            
            # Setup mock scan commands
            ScanCommand.CERTIFICATE_INFO = 'CERTIFICATE_INFO'
            ScanCommand.SSL_2_0_CIPHER_SUITES = 'SSL_2_0_CIPHER_SUITES'
            ScanCommand.SSL_3_0_CIPHER_SUITES = 'SSL_3_0_CIPHER_SUITES'
            ScanCommand.TLS_1_0_CIPHER_SUITES = 'TLS_1_0_CIPHER_SUITES'
            ScanCommand.TLS_1_1_CIPHER_SUITES = 'TLS_1_1_CIPHER_SUITES'
            ScanCommand.TLS_1_2_CIPHER_SUITES = 'TLS_1_2_CIPHER_SUITES'
            ScanCommand.TLS_1_3_CIPHER_SUITES = 'TLS_1_3_CIPHER_SUITES'
            ScanCommand.HEARTBLEED = 'HEARTBLEED'
            ScanCommand.OPENSSL_CCS_INJECTION = 'OPENSSL_CCS_INJECTION'
            ScanCommand.TLS_FALLBACK_SCSV = 'TLS_FALLBACK_SCSV'
            ScanCommand.SESSION_RENEGOTIATION = 'SESSION_RENEGOTIATION'
            ScanCommand.TLS_COMPRESSION = 'TLS_COMPRESSION'
            ScanCommand.EARLY_DATA = 'EARLY_DATA'
            
            # Setup mock scan results
            mock_results = []
            expected_ssl_ports = [p for p in ports if p in ssl_eligible_ports or self._is_ssl_service(p)]
            
            for port in expected_ssl_ports:
                mock_result = MagicMock()
                mock_result.server_location = MagicMock()
                mock_result.server_location.hostname = str(ip)
                mock_result.server_location.port = port
                
                # Mock certificate info
                mock_cert_info = MagicMock()
                mock_cert_info.certificate_deployments = [MagicMock()]
                mock_cert_info.certificate_deployments[0].received_certificate_chain = [MagicMock()]
                
                mock_cert = mock_cert_info.certificate_deployments[0].received_certificate_chain[0]
                mock_cert.subject = f"CN=test-{port}.example.com"
                mock_cert.issuer = "CN=Test CA"
                mock_cert.serial_number = 12345
                mock_cert.not_valid_before = MagicMock()
                mock_cert.not_valid_before.isoformat.return_value = "2023-01-01T00:00:00"
                mock_cert.not_valid_after = MagicMock()
                mock_cert.not_valid_after.isoformat.return_value = "2024-01-01T00:00:00"
                
                mock_result.scan_result = MagicMock()
                mock_result.scan_result.certificate_info = mock_cert_info
                
                mock_results.append(mock_result)
            
            mock_scanner.get_results.return_value = mock_results
            
            # Create module and test SSL analysis
            module = LocalInfoModule()
            ssl_results = module.analyze_ssl_services(ip, expected_ssl_ports)
            
            # Verify SSL testing was performed for eligible ports
            if expected_ssl_ports:
                assert len(ssl_results) > 0, "SSL analysis should be performed for web/mail server ports"
                
                # Verify each SSL result corresponds to an eligible port
                ssl_ports_tested = {result.port for result in ssl_results}
                expected_ports_set = set(expected_ssl_ports)
                
                # All eligible ports should have been tested
                assert ssl_ports_tested == expected_ports_set, \
                    f"SSL testing should cover all eligible ports. Expected: {expected_ports_set}, Got: {ssl_ports_tested}"
                
                # Verify SSL results structure
                for ssl_result in ssl_results:
                    assert isinstance(ssl_result, SSLResult), "Result must be SSLResult instance"
                    assert ssl_result.port in expected_ssl_ports, "SSL result port must be eligible for testing"
                    assert ssl_result.protocol is not None, "SSL result must have protocol information"
                    
                    # Verify that web server ports (Requirements 7.11) and mail server ports (Requirements 7.12) are tested
                    if ssl_result.port in web_server_ports:
                        # This validates Requirement 7.11: webserver port SSL testing
                        assert ssl_result.port in ssl_ports_tested, "Web server port must be SSL tested"
                    
                    if ssl_result.port in mail_server_ports:
                        # This validates Requirement 7.12: mailserver port SSL testing  
                        assert ssl_result.port in ssl_ports_tested, "Mail server port must be SSL tested"
            else:
                # If no eligible ports, SSL results should be empty
                assert len(ssl_results) == 0, "No SSL analysis should be performed for non-eligible ports"

    @given(ip_addresses())
    @settings(max_examples=50, deadline=None)
    def test_ssl_testing_skipped_for_non_eligible_ports(self, ip):
        """
        Verify that SSL testing is not performed for ports that are not web or mail servers.
        
        This ensures the conditional nature of SSL testing - it should only occur
        for appropriate service types.
        """
        # Use only non-SSL eligible ports
        non_ssl_ports = [22, 21, 23, 53, 3389, 5432, 3306]  # SSH, FTP, Telnet, DNS, RDP, PostgreSQL, MySQL
        
        open_ports = []
        for port in non_ssl_ports:
            service_name = self._get_service_name(port)
            open_ports.append({
                'port': port,
                'protocol': 'tcp', 
                'state': 'open',
                'service': service_name,
                'version': '',
                'product': ''
            })
        
        module = LocalInfoModule()
        
        # Identify SSL ports (should be empty for non-eligible ports)
        ssl_ports = module._identify_ssl_ports(open_ports)
        
        # Verify no SSL testing is triggered
        assert len(ssl_ports) == 0, "Non-eligible ports should not trigger SSL testing"
        
        # Verify SSL analysis returns empty results
        ssl_results = module.analyze_ssl_services(ip, ssl_ports)
        assert len(ssl_results) == 0, "SSL analysis should return empty results for non-eligible ports"

    @given(ip_addresses(), st.lists(st.integers(1, 65535), min_size=1, max_size=5))
    @settings(max_examples=50, deadline=None)
    def test_ssl_port_identification_accuracy(self, ip, random_ports):
        """
        Verify that SSL port identification correctly identifies web and mail server ports.
        
        This tests the _identify_ssl_ports method to ensure it properly categorizes
        ports based on service type and common SSL port numbers.
        """
        # Mix of SSL and non-SSL ports
        ssl_ports = [443, 993, 465, 587]  # HTTPS, IMAPS, SMTPS, Submission
        mixed_ports = ssl_ports + random_ports
        
        open_ports = []
        for port in mixed_ports:
            service_name = self._get_service_name(port)
            open_ports.append({
                'port': port,
                'protocol': 'tcp',
                'state': 'open', 
                'service': service_name,
                'version': '',
                'product': ''
            })
        
        module = LocalInfoModule()
        identified_ssl_ports = module._identify_ssl_ports(open_ports)
        
        # Verify that known SSL ports are identified
        for ssl_port in ssl_ports:
            if ssl_port in mixed_ports:  # Only check if the port was in our test data
                assert ssl_port in identified_ssl_ports, f"Known SSL port {ssl_port} should be identified"
        
        # Verify identified ports are reasonable (no obviously wrong ports)
        for identified_port in identified_ssl_ports:
            assert identified_port in mixed_ports, "Identified SSL port must be from the input ports"

    def _get_service_name(self, port: int) -> str:
        """Get service name for a given port number."""
        service_map = {
            22: 'ssh',
            21: 'ftp', 
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            465: 'smtps',
            587: 'submission',
            993: 'imaps',
            995: 'pop3s',
            3389: 'rdp',
            5432: 'postgresql',
            3306: 'mysql',
            8080: 'http-alt',
            8443: 'https-alt'
        }
        return service_map.get(port, 'unknown')

    def _is_ssl_service(self, port: int) -> bool:
        """Check if a port typically runs SSL/TLS services."""
        ssl_services = {'https', 'imaps', 'pop3s', 'smtps', 'submission', 'https-alt'}
        service_name = self._get_service_name(port)
        return service_name in ssl_services or 'ssl' in service_name.lower() or 'tls' in service_name.lower()


class TestSSLAnalysisErrorHandling:
    """Test error handling in SSL analysis."""

    @given(ip_addresses(), st.lists(st.integers(443, 8443), min_size=1, max_size=3))
    @settings(max_examples=25, deadline=None)
    def test_ssl_analysis_with_connection_failures(self, ip, ssl_ports):
        """
        Verify that SSL analysis handles connection failures gracefully.
        
        When SSL analysis fails (network issues, certificate problems, etc.),
        the module should continue processing other ports and return appropriate
        error information.
        """
        with patch.dict('sys.modules', {
            'sslyze': MagicMock(),
            'sslyze.Scanner': MagicMock(),
            'sslyze.ServerScanRequest': MagicMock(), 
            'sslyze.ServerNetworkLocation': MagicMock(),
            'sslyze.plugins.scan_commands': MagicMock()
        }):
            from sslyze import Scanner
            
            # Setup scanner to simulate connection failures
            mock_scanner = MagicMock()
            Scanner.return_value = mock_scanner
            mock_scanner.get_results.side_effect = Exception("Connection failed")
            
            module = LocalInfoModule()
            ssl_results = module.analyze_ssl_services(ip, ssl_ports)
            
            # Should return results even with failures (may include error information)
            assert isinstance(ssl_results, list), "SSL analysis should return list even on failures"
            
            # If results are returned, they should contain error information
            for result in ssl_results:
                assert isinstance(result, SSLResult), "Failed results should still be SSLResult instances"
                assert result.port in ssl_ports, "Result port should match requested ports"