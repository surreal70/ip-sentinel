#!/usr/bin/env python3
"""
Test script to verify HTML formatter correctly displays all cipher suites
and port-specific information for SSL/TLS certificates.
"""

from src.ip_sentinel.formatters.html import HTMLFormatter
from src.ip_sentinel.config import ReportingMode


def test_ssl_results_with_multiple_ports():
    """Test that SSL results with same certificate on multiple ports show all details."""
    
    # Create test data with same certificate on multiple ports
    ssl_results = [
        {
            'port': 443,
            'protocol': 'TLS',
            'certificate': {
                'subject': 'CN=example.com',
                'issuer': 'CN=Test CA',
                'not_valid_before': '2024-01-01',
                'not_valid_after': '2025-01-01',
                'shared_across_ports': [443, 8443]
            },
            'cipher_suites': [
                'TLS_1_2: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_1_2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_1_2: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_1_3: TLS_AES_256_GCM_SHA384',
                'TLS_1_3: TLS_AES_128_GCM_SHA256',
                'TLS_1_3: TLS_CHACHA20_POLY1305_SHA256'
            ],
            'vulnerabilities': []
        },
        {
            'port': 8443,
            'protocol': 'TLS',
            'certificate': {
                'reference_to_port': 443,
                'note': 'Identical certificate - see primary port for details'
            },
            'cipher_suites': [
                'TLS_1_2: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_1_2: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_1_2: TLS_RSA_WITH_AES_256_CBC_SHA',
                'TLS_1_3: TLS_AES_256_GCM_SHA384'
            ],
            'vulnerabilities': ['TLS 1.0 enabled (MEDIUM - deprecated)']
        }
    ]
    
    result_data = {
        'ip_address': '192.168.1.100',
        'scan_timestamp': '2024-01-15 10:30:00',
        'local_info': {
            'ssl_results': ssl_results
        }
    }
    
    formatter = HTMLFormatter(ReportingMode.NORMAL)
    html_output = formatter.format_result(result_data)
    
    # Verify all cipher suites are present (not truncated to 5)
    print("Checking for cipher suites in HTML output...")
    assert 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' in html_output, "Missing cipher suite 1"
    assert 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' in html_output, "Missing cipher suite 2"
    assert 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384' in html_output, "Missing cipher suite 3"
    assert 'TLS_AES_256_GCM_SHA384' in html_output, "Missing cipher suite 4"
    assert 'TLS_AES_128_GCM_SHA256' in html_output, "Missing cipher suite 5"
    assert 'TLS_CHACHA20_POLY1305_SHA256' in html_output, "Missing cipher suite 6"
    print("✓ All cipher suites from port 443 are present")
    
    # Verify port-specific cipher suites are shown
    assert 'TLS_RSA_WITH_AES_256_CBC_SHA' in html_output, "Missing port-specific cipher suite"
    print("✓ Port-specific cipher suite from port 8443 is present")
    
    # Verify both ports are mentioned
    assert 'Port 443' in html_output or '443' in html_output, "Port 443 not mentioned"
    assert 'Port 8443' in html_output or '8443' in html_output, "Port 8443 not mentioned"
    print("✓ Both ports are mentioned in the output")
    
    # Verify port-specific vulnerabilities are shown
    assert 'TLS 1.0 enabled' in html_output, "Missing port-specific vulnerability"
    print("✓ Port-specific vulnerability is present")
    
    # Verify no truncation message
    assert '... and' not in html_output or 'more</li>' not in html_output, "Cipher suites appear to be truncated"
    print("✓ No cipher suite truncation detected")
    
    print("\n✅ All tests passed! HTML formatter correctly displays:")
    print("   - All cipher suites (not limited to 5)")
    print("   - Port-specific cipher suites for each port")
    print("   - Port-specific vulnerabilities")
    print("   - Both ports with the same certificate")
    
    # Save output for manual inspection
    with open('test_ssl_output.html', 'w') as f:
        f.write(html_output)
    print("\n📄 Full HTML output saved to: test_ssl_output.html")


if __name__ == '__main__':
    test_ssl_results_with_multiple_ports()
