"""
Integration tests for UX enhancements (Task 25).

Tests the following enhancements:
- --human flag with all output modes
- --run-root flag behavior
- Improved readability across different terminal types
- Tree-like traceroute visualization
- NAT detection with RFC 1918 addresses
- --no-cert-check option
"""

import pytest
from ipaddress import IPv4Address
from ip_sentinel.config import Config
from ip_sentinel.modules.local_info import LocalInfoModule
from ip_sentinel.formatters.human import HumanFormatter
from ip_sentinel.formatters.html import HTMLFormatter


class TestHumanFormatFlag:
    """Test --human flag with all output modes."""

    def test_human_format_is_default(self):
        """Test that human format is the default."""
        config = Config()
        assert config.output_format == "human"

    def test_human_format_explicit(self):
        """Test explicit --human flag."""
        config = Config(output_format="human")
        assert config.output_format == "human"

    def test_json_format_overrides_default(self):
        """Test that --json overrides default."""
        config = Config(output_format="json")
        assert config.output_format == "json"

    def test_html_format_overrides_default(self):
        """Test that --html overrides default."""
        config = Config(output_format="html")
        assert config.output_format == "html"


class TestRunRootFlag:
    """Test --run-root flag behavior."""

    def test_run_root_default_false(self):
        """Test that run_root defaults to False."""
        config = Config()
        assert config.run_root is False

    def test_run_root_explicit_true(self):
        """Test explicit --run-root flag."""
        config = Config(run_root=True)
        assert config.run_root is True

    def test_local_info_module_respects_run_root(self):
        """Test that LocalInfoModule respects run_root setting."""
        module_with_root = LocalInfoModule(run_root=True)
        assert module_with_root.run_root is True

        module_without_root = LocalInfoModule(run_root=False)
        assert module_without_root.run_root is False

    def test_root_privilege_detection(self):
        """Test root privilege detection method."""
        # This test just verifies the method exists and returns a boolean
        has_root = LocalInfoModule.has_root_privileges()
        assert isinstance(has_root, bool)


class TestImprovedReadability:
    """Test improved readability of output."""

    def test_human_formatter_color_support_detection(self):
        """Test that human formatter detects color support."""
        formatter = HumanFormatter()
        # Should have a use_colors attribute
        assert hasattr(formatter, 'use_colors')
        assert isinstance(formatter.use_colors, bool)

    def test_human_formatter_section_headers(self):
        """Test that human formatter creates section headers."""
        formatter = HumanFormatter()
        header = formatter._section_header("Test Section")
        assert "Test Section" in header
        assert len(header) > len("Test Section")  # Should have formatting

    def test_human_formatter_key_value_formatting(self):
        """Test key-value formatting."""
        formatter = HumanFormatter()
        formatted = formatter._format_key_value("Test Key", "Test Value")
        assert "Test Key" in formatted
        assert "Test Value" in formatted


class TestTracerouteTreeVisualization:
    """Test tree-like traceroute visualization."""

    def test_human_formatter_traceroute_tree(self):
        """Test traceroute tree formatting in human output."""
        formatter = HumanFormatter()
        output_lines = []

        traceroute_results = [
            {
                'method': 'traditional',
                'success': True,
                'hops': [
                    {'hop': 1, 'ip': '192.168.1.1', 'hostname': 'gateway', 'rtt': 1.5},
                    {'hop': 2, 'ip': '10.0.0.1', 'hostname': None, 'rtt': 5.2},
                    {'hop': 3, 'ip': '8.8.8.8', 'hostname': 'dns.google', 'rtt': 15.3, 'reached_destination': True}
                ]
            }
        ]

        formatter._format_traceroute_tree(traceroute_results, output_lines)

        # Verify tree structure is present
        output_text = '\n'.join(output_lines)
        assert 'Traceroute' in output_text
        assert 'traditional' in output_text.lower()
        assert '├──' in output_text or '└──' in output_text  # Tree characters

    def test_html_formatter_traceroute_tree(self):
        """Test traceroute tree formatting in HTML output."""
        formatter = HTMLFormatter()

        traceroute_results = [
            {
                'method': 'ping',
                'success': True,
                'hops': [
                    {'hop': 1, 'ip': '192.168.1.1', 'rtt': 1.5},
                    {'hop': 2, 'ip': '10.0.0.1', 'rtt': 5.2}
                ]
            }
        ]

        html_output = formatter._format_traceroute_tree_html(traceroute_results)

        # Verify HTML structure
        assert 'traceroute' in html_output.lower()
        assert 'ping' in html_output.lower()
        assert '192.168.1.1' in html_output


class TestNATDetection:
    """Test NAT detection for RFC 1918 addresses."""

    def test_rfc1918_detection(self):
        """Test RFC 1918 address detection."""
        module = LocalInfoModule()

        # Test RFC 1918 addresses
        assert module._is_rfc1918_address(IPv4Address('10.0.0.1')) is True
        assert module._is_rfc1918_address(IPv4Address('172.16.0.1')) is True
        assert module._is_rfc1918_address(IPv4Address('192.168.1.1')) is True

        # Test non-RFC 1918 addresses
        assert module._is_rfc1918_address(IPv4Address('8.8.8.8')) is False
        assert module._is_rfc1918_address(IPv4Address('1.1.1.1')) is False

    def test_nat_detection_structure(self):
        """Test NAT detection returns proper structure."""
        module = LocalInfoModule(enable_nat_detection=True)
        ip = IPv4Address('192.168.1.100')

        # This will likely fail to get public IP in test environment, but should return proper structure
        result = module._detect_nat(ip)

        # Verify structure
        assert 'detected' in result
        assert 'private_ip' in result
        assert 'public_ip' in result
        assert 'nat_type' in result
        assert 'error' in result
        assert result['private_ip'] == '192.168.1.100'

    def test_nat_detection_can_be_disabled(self):
        """Test that NAT detection can be disabled."""
        module = LocalInfoModule(enable_nat_detection=False)
        assert module.enable_nat_detection is False


class TestNoCertCheckOption:
    """Test --no-cert-check option."""

    def test_verify_ssl_default_true(self):
        """Test that verify_ssl defaults to True."""
        config = Config()
        assert config.verify_ssl is True

    def test_verify_ssl_can_be_disabled(self):
        """Test that verify_ssl can be set to False."""
        config = Config(verify_ssl=False)
        assert config.verify_ssl is False

    def test_local_info_module_respects_verify_ssl(self):
        """Test that LocalInfoModule respects verify_ssl setting."""
        module_with_verify = LocalInfoModule(verify_ssl=True)
        assert module_with_verify.verify_ssl is True

        module_without_verify = LocalInfoModule(verify_ssl=False)
        assert module_without_verify.verify_ssl is False


class TestIntegrationOfAllEnhancements:
    """Test that all enhancements work together."""

    def test_config_with_all_enhancements(self):
        """Test Config with all enhancement flags."""
        config = Config(
            output_format="human",
            run_root=True,
            verify_ssl=False
        )

        assert config.output_format == "human"
        assert config.run_root is True
        assert config.verify_ssl is False

    def test_local_info_module_with_all_enhancements(self):
        """Test LocalInfoModule with all enhancement flags."""
        module = LocalInfoModule(
            run_root=True,
            enable_nat_detection=True,
            verify_ssl=False
        )

        assert module.run_root is True
        assert module.enable_nat_detection is True
        assert module.verify_ssl is False

    def test_formatters_work_with_enhanced_data(self):
        """Test that formatters handle enhanced data structures."""
        # Create sample data with all enhancements
        sample_data = {
            'ip_address': '192.168.1.100',
            'scan_timestamp': '2026-01-18 12:00:00',
            'classifications': [
                {
                    'name': 'private_ipv4_192',
                    'ip_range': '192.168.0.0/16',
                    'description': 'Private IPv4 addresses',
                    'qualifies_for': ['local_info']
                }
            ],
            'local_info': {
                'is_local_subnet': True,
                'reachable': True,
                'nat_detection': {
                    'detected': True,
                    'private_ip': '192.168.1.100',
                    'public_ip': '203.0.113.1',
                    'nat_type': 'NAT detected (likely SNAT/PAT)'
                },
                'traceroute_results': [
                    {
                        'method': 'traditional',
                        'success': True,
                        'hops': [
                            {'hop': 1, 'ip': '192.168.1.1', 'rtt': 1.5}
                        ]
                    }
                ]
            }
        }

        # Test human formatter
        human_formatter = HumanFormatter()
        human_output = human_formatter.format_result(sample_data)
        assert len(human_output) > 0
        assert '192.168.1.100' in human_output

        # Test HTML formatter
        html_formatter = HTMLFormatter()
        html_output = html_formatter.format_result(sample_data)
        assert len(html_output) > 0
        assert '192.168.1.100' in html_output
        assert '<html' in html_output.lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
