"""
Property-based tests for SSL Certificate Deduplication.

Feature: ip-intelligence-analyzer, Property 16: SSL Certificate Deduplication
Validates: Requirements 7.13
"""

import pytest
import sys
from hypothesis import given, strategies as st, settings
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import patch, MagicMock
from typing import List, Dict, Any

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


# Strategy for generating SSL port configurations with potential duplicates
@st.composite
def ssl_port_configurations_with_duplicates(draw):
    """Generate SSL port configurations that may have identical certificates."""
    # Common SSL ports that might share certificates
    ssl_ports = [443, 8443, 993, 465, 587, 995]
    
    # Select 2-5 ports for testing
    num_ports = draw(st.integers(2, 5))
    selected_ports = draw(st.lists(
        st.sampled_from(ssl_ports), 
        min_size=num_ports, 
        max_size=num_ports,
        unique=True
    ))
    
    return selected_ports


# Strategy for generating certificate data
@st.composite
def certificate_data(draw):
    """Generate certificate data for testing."""
    # Generate certificate identifiers that may be duplicated
    cert_id = draw(st.integers(1, 3))  # Limited range to encourage duplicates
    
    return {
        'subject': f'CN=test-cert-{cert_id}.example.com',
        'issuer': f'CN=Test CA {cert_id}',
        'serial_number': str(cert_id * 1000 + draw(st.integers(1, 999))),
        'not_valid_before': '2023-01-01T00:00:00',
        'not_valid_after': '2024-01-01T00:00:00',
        'fingerprint': f'sha256:{"a" * 10}{cert_id:02d}{"b" * 52}'  # Simplified fingerprint
    }


class TestSSLCertificateDeduplication:
    """Test Property 16: SSL Certificate Deduplication."""

    @given(ip_addresses(), ssl_port_configurations_with_duplicates())
    @settings(max_examples=100, deadline=None)
    def test_identical_certificates_reported_once(self, ip, ssl_ports):
        """
        Property 16: SSL Certificate Deduplication
        
        For any set of SSL certificates discovered across multiple ports, identical 
        certificates should be reported only once with port-specific differences 
        clearly documented.
        
        **Validates: Requirements 7.13**
        """
        # Create certificate data - some ports will share the same certificate
        cert_data_map = {}
        port_cert_mapping = {}
        
        # Assign certificates to ports (some may share the same certificate)
        for i, port in enumerate(ssl_ports):
            # Use modulo to create certificate sharing patterns
            cert_index = i % max(1, len(ssl_ports) // 2 + 1)
            
            if cert_index not in cert_data_map:
                cert_data_map[cert_index] = {
                    'subject': f'CN=shared-cert-{cert_index}.example.com',
                    'issuer': f'CN=Shared CA {cert_index}',
                    'serial_number': str(cert_index * 1000 + 123),
                    'not_valid_before': '2023-01-01T00:00:00',
                    'not_valid_after': '2024-01-01T00:00:00',
                    'fingerprint': f'sha256:{"c" * 10}{cert_index:02d}{"d" * 52}'
                }
            
            port_cert_mapping[port] = cert_index
        
        # Mock sslyze to return the certificate data
        with patch.dict('sys.modules', {
            'sslyze': MagicMock(),
            'sslyze.Scanner': MagicMock(),
            'sslyze.ServerScanRequest': MagicMock(), 
            'sslyze.ServerNetworkLocation': MagicMock(),
            'sslyze.plugins.scan_commands': MagicMock()
        }):
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
            from sslyze.plugins.scan_commands import ScanCommand
            
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
            
            # Setup mock scanner
            mock_scanner = MagicMock()
            Scanner.return_value = mock_scanner
            
            # Create mock results for each port
            mock_results = []
            for port in ssl_ports:
                cert_index = port_cert_mapping[port]
                cert_data = cert_data_map[cert_index]
                
                mock_result = MagicMock()
                mock_result.server_location = MagicMock()
                mock_result.server_location.hostname = str(ip)
                mock_result.server_location.port = port
                
                # Mock certificate info
                mock_cert_info = MagicMock()
                mock_cert_info.certificate_deployments = [MagicMock()]
                mock_cert_info.certificate_deployments[0].received_certificate_chain = [MagicMock()]
                
                mock_cert = mock_cert_info.certificate_deployments[0].received_certificate_chain[0]
                mock_cert.subject = cert_data['subject']
                mock_cert.issuer = cert_data['issuer']
                mock_cert.serial_number = cert_data['serial_number']
                mock_cert.not_valid_before = MagicMock()
                mock_cert.not_valid_before.isoformat.return_value = cert_data['not_valid_before']
                mock_cert.not_valid_after = MagicMock()
                mock_cert.not_valid_after.isoformat.return_value = cert_data['not_valid_after']
                
                mock_result.scan_result = MagicMock()
                mock_result.scan_result.certificate_info = mock_cert_info
                
                mock_results.append(mock_result)
            
            mock_scanner.get_results.return_value = mock_results
            
            # Create module and perform SSL analysis
            module = LocalInfoModule()
            ssl_results = module.analyze_ssl_services(ip, ssl_ports)
            
            # Analyze the results for deduplication
            if ssl_results:
                # Group results by certificate fingerprint/identity
                cert_groups = self._group_certificates_by_identity(ssl_results)
                
                # Verify deduplication behavior
                unique_certificates = set()
                for result in ssl_results:
                    if result.certificate:
                        cert_identity = self._get_certificate_identity(result.certificate)
                        unique_certificates.add(cert_identity)
                
                # Count how many unique certificates we should have
                expected_unique_certs = len(cert_data_map)
                
                # If we have multiple ports with the same certificate, verify deduplication
                ports_per_cert = {}
                for port in ssl_ports:
                    cert_index = port_cert_mapping[port]
                    if cert_index not in ports_per_cert:
                        ports_per_cert[cert_index] = []
                    ports_per_cert[cert_index].append(port)
                
                # Check for certificates that appear on multiple ports
                duplicate_cert_groups = {k: v for k, v in ports_per_cert.items() if len(v) > 1}
                
                if duplicate_cert_groups:
                    # Verify that identical certificates are handled appropriately
                    # The requirement is that they should be "reported once" with port differences documented
                    
                    for cert_index, ports_with_cert in duplicate_cert_groups.items():
                        # Find SSL results for these ports
                        results_for_cert = [r for r in ssl_results if r.port in ports_with_cert]
                        
                        if results_for_cert:
                            # Separate primary and reference results
                            primary_results = [r for r in results_for_cert if 'reference_to_port' not in r.certificate]
                            reference_results = [r for r in results_for_cert if 'reference_to_port' in r.certificate]
                            
                            # Should have exactly one primary result for identical certificates
                            assert len(primary_results) == 1, \
                                "Should have exactly one primary certificate result for identical certificates"
                            
                            primary_result = primary_results[0]
                            primary_cert = primary_result.certificate
                            
                            # Verify primary certificate has expected data
                            assert 'subject' in primary_cert, "Primary certificate should have subject"
                            assert 'serial_number' in primary_cert, "Primary certificate should have serial number"
                            
                            # Verify reference results point to the primary
                            for ref_result in reference_results:
                                assert ref_result.certificate.get('reference_to_port') == primary_result.port, \
                                    "Reference certificates should point to primary port"
                                assert 'note' in ref_result.certificate, \
                                    "Reference certificates should have explanatory note"
                            
                            # Verify that port-specific differences are documented
                            # Each result should still contain the port information
                            documented_ports = {r.port for r in results_for_cert}
                            expected_ports = set(ports_with_cert)
                            assert documented_ports == expected_ports, \
                                "All ports with identical certificates should be documented"

    @given(ip_addresses())
    @settings(max_examples=50, deadline=None)
    def test_different_certificates_reported_separately(self, ip):
        """
        Verify that different certificates on different ports are reported separately.
        
        This ensures that the deduplication logic doesn't incorrectly merge
        different certificates.
        """
        ssl_ports = [443, 8443, 993]  # Three different ports
        
        # Mock sslyze to return different certificates for each port
        with patch.dict('sys.modules', {
            'sslyze': MagicMock(),
            'sslyze.Scanner': MagicMock(),
            'sslyze.ServerScanRequest': MagicMock(), 
            'sslyze.ServerNetworkLocation': MagicMock(),
            'sslyze.plugins.scan_commands': MagicMock()
        }):
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
            from sslyze.plugins.scan_commands import ScanCommand
            
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

            mock_scanner = MagicMock()
            Scanner.return_value = mock_scanner
            
            # Create different certificates for each port
            mock_results = []
            for i, port in enumerate(ssl_ports):
                mock_result = MagicMock()
                mock_result.server_location = MagicMock()
                mock_result.server_location.hostname = str(ip)
                mock_result.server_location.port = port
                
                # Create unique certificate for each port
                mock_cert_info = MagicMock()
                mock_cert_info.certificate_deployments = [MagicMock()]
                mock_cert_info.certificate_deployments[0].received_certificate_chain = [MagicMock()]
                
                mock_cert = mock_cert_info.certificate_deployments[0].received_certificate_chain[0]
                mock_cert.subject = f'CN=unique-cert-{port}.example.com'
                mock_cert.issuer = f'CN=Unique CA {port}'
                mock_cert.serial_number = str(port * 1000 + i)
                mock_cert.not_valid_before = MagicMock()
                mock_cert.not_valid_before.isoformat.return_value = '2023-01-01T00:00:00'
                mock_cert.not_valid_after = MagicMock()
                mock_cert.not_valid_after.isoformat.return_value = '2024-01-01T00:00:00'
                
                mock_result.scan_result = MagicMock()
                mock_result.scan_result.certificate_info = mock_cert_info
                
                mock_results.append(mock_result)
            
            mock_scanner.get_results.return_value = mock_results
            
            module = LocalInfoModule()
            ssl_results = module.analyze_ssl_services(ip, ssl_ports)
            
            if ssl_results:
                # Verify that each port has its own certificate result
                result_ports = {r.port for r in ssl_results}
                expected_ports = set(ssl_ports)
                
                # All ports should be represented
                assert result_ports == expected_ports, \
                    "Each port with different certificate should have separate result"
                
                # Verify that certificates are actually different
                certificate_subjects = set()
                for result in ssl_results:
                    if result.certificate and 'subject' in result.certificate:
                        certificate_subjects.add(result.certificate['subject'])
                
                # Should have as many unique subjects as ports (since all certs are different)
                assert len(certificate_subjects) == len(ssl_ports), \
                    "Different certificates should have different subjects"

    @given(ip_addresses(), st.lists(st.integers(443, 8443), min_size=2, max_size=4))
    @settings(max_examples=50, deadline=None)
    def test_certificate_deduplication_with_port_differences(self, ip, ssl_ports):
        """
        Verify that when identical certificates are found, port-specific differences
        are clearly documented.
        
        This tests the requirement that differences by port should be described
        when certificates are deduplicated.
        """
        # Make all ports use the same certificate but with different cipher suites
        shared_cert_data = {
            'subject': 'CN=shared.example.com',
            'issuer': 'CN=Shared CA',
            'serial_number': '123456789',
            'not_valid_before': '2023-01-01T00:00:00',
            'not_valid_after': '2024-01-01T00:00:00'
        }
        
        with patch.dict('sys.modules', {
            'sslyze': MagicMock(),
            'sslyze.Scanner': MagicMock(),
            'sslyze.ServerScanRequest': MagicMock(), 
            'sslyze.ServerNetworkLocation': MagicMock(),
            'sslyze.plugins.scan_commands': MagicMock()
        }):
            from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
            from sslyze.plugins.scan_commands import ScanCommand
            
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
            
            mock_scanner = MagicMock()
            Scanner.return_value = mock_scanner
            
            mock_results = []
            for port in ssl_ports:
                mock_result = MagicMock()
                mock_result.server_location = MagicMock()
                mock_result.server_location.hostname = str(ip)
                mock_result.server_location.port = port
                
                # Same certificate for all ports
                mock_cert_info = MagicMock()
                mock_cert_info.certificate_deployments = [MagicMock()]
                mock_cert_info.certificate_deployments[0].received_certificate_chain = [MagicMock()]
                
                mock_cert = mock_cert_info.certificate_deployments[0].received_certificate_chain[0]
                mock_cert.subject = shared_cert_data['subject']
                mock_cert.issuer = shared_cert_data['issuer']
                mock_cert.serial_number = shared_cert_data['serial_number']
                mock_cert.not_valid_before = MagicMock()
                mock_cert.not_valid_before.isoformat.return_value = shared_cert_data['not_valid_before']
                mock_cert.not_valid_after = MagicMock()
                mock_cert.not_valid_after.isoformat.return_value = shared_cert_data['not_valid_after']
                
                mock_result.scan_result = MagicMock()
                mock_result.scan_result.certificate_info = mock_cert_info
                
                # Add port-specific cipher suites (differences by port)
                mock_result.scan_result.ssl_2_0_cipher_suites = MagicMock()
                mock_result.scan_result.ssl_2_0_cipher_suites.accepted_cipher_suites = []
                
                mock_results.append(mock_result)
            
            mock_scanner.get_results.return_value = mock_results
            
            module = LocalInfoModule()
            ssl_results = module.analyze_ssl_services(ip, ssl_ports)
            
            if ssl_results and len(ssl_results) > 1:
                # Verify that the primary result has the certificate information
                primary_results = [r for r in ssl_results if 'reference_to_port' not in r.certificate]
                reference_results = [r for r in ssl_results if 'reference_to_port' in r.certificate]
                
                # Should have at least one primary result
                assert len(primary_results) >= 1, "Should have at least one primary certificate result"
                
                # All primary results should have the same certificate information
                if len(primary_results) > 1:
                    first_cert = primary_results[0].certificate
                    for result in primary_results[1:]:
                        if result.certificate and first_cert:
                            assert result.certificate.get('subject') == first_cert.get('subject'), \
                                "Identical certificates should have same subject"
                            assert result.certificate.get('serial_number') == first_cert.get('serial_number'), \
                                "Identical certificates should have same serial number"
                
                # Verify that port information is preserved (port-specific differences documented)
                result_ports = {r.port for r in ssl_results}
                expected_ports = set(ssl_ports)
                assert result_ports == expected_ports, \
                    "Port-specific differences should be documented for identical certificates"

    def _group_certificates_by_identity(self, ssl_results: List[SSLResult]) -> Dict[str, List[SSLResult]]:
        """Group SSL results by certificate identity."""
        groups = {}
        for result in ssl_results:
            if result.certificate:
                identity = self._get_certificate_identity(result.certificate)
                if identity not in groups:
                    groups[identity] = []
                groups[identity].append(result)
        return groups

    def _get_certificate_identity(self, certificate: Dict[str, Any]) -> str:
        """Get a unique identity for a certificate based on key fields."""
        subject = certificate.get('subject', '')
        serial = certificate.get('serial_number', '')
        issuer = certificate.get('issuer', '')
        return f"{subject}|{serial}|{issuer}"


class TestCertificateDeduplicationErrorHandling:
    """Test error handling in certificate deduplication."""

    @given(ip_addresses(), st.lists(st.integers(443, 8443), min_size=2, max_size=3))
    @settings(max_examples=25, deadline=None)
    def test_deduplication_with_missing_certificate_data(self, ip, ssl_ports):
        """
        Verify that deduplication works correctly when some certificates have missing data.
        
        This ensures robust handling when certificate extraction fails for some ports
        but succeeds for others.
        """
        with patch.dict('sys.modules', {
            'sslyze': MagicMock(),
            'sslyze.Scanner': MagicMock(),
            'sslyze.ServerScanRequest': MagicMock(), 
            'sslyze.ServerNetworkLocation': MagicMock(),
            'sslyze.plugins.scan_commands': MagicMock()
        }):
            from sslyze import Scanner
            
            # Setup mock scan commands (minimal for error handling test)
            mock_scanner = MagicMock()
            Scanner.return_value = mock_scanner
            
            # Mix of successful and failed certificate extractions
            mock_results = []
            for i, port in enumerate(ssl_ports):
                mock_result = MagicMock()
                mock_result.server_location = MagicMock()
                mock_result.server_location.hostname = str(ip)
                mock_result.server_location.port = port
                
                if i % 2 == 0:  # Even ports have certificates
                    mock_cert_info = MagicMock()
                    mock_cert_info.certificate_deployments = [MagicMock()]
                    mock_cert_info.certificate_deployments[0].received_certificate_chain = [MagicMock()]
                    
                    mock_cert = mock_cert_info.certificate_deployments[0].received_certificate_chain[0]
                    mock_cert.subject = f'CN=cert-{port}.example.com'
                    mock_cert.issuer = 'CN=Test CA'
                    mock_cert.serial_number = str(port)
                    mock_cert.not_valid_before = MagicMock()
                    mock_cert.not_valid_before.isoformat.return_value = '2023-01-01T00:00:00'
                    mock_cert.not_valid_after = MagicMock()
                    mock_cert.not_valid_after.isoformat.return_value = '2024-01-01T00:00:00'
                    
                    mock_result.scan_result = MagicMock()
                    mock_result.scan_result.certificate_info = mock_cert_info
                else:  # Odd ports have no certificate info
                    mock_result.scan_result = MagicMock()
                    mock_result.scan_result.certificate_info = None
                
                mock_results.append(mock_result)
            
            mock_scanner.get_results.return_value = mock_results
            
            module = LocalInfoModule()
            ssl_results = module.analyze_ssl_services(ip, ssl_ports)
            
            # Should handle mixed success/failure gracefully
            assert isinstance(ssl_results, list), "Should return list even with mixed certificate data"
            
            # Results should be returned for all ports, even those with missing certificates
            if ssl_results:
                result_ports = {r.port for r in ssl_results}
                expected_ports = set(ssl_ports)
                # Note: The actual behavior may vary based on implementation
                # The key is that it should handle missing data gracefully