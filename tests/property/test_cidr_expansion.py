"""
Property-based tests for CIDR expansion accuracy.

Feature: ip-intelligence-analyzer, Property 24: CIDR Expansion Accuracy
Validates: Requirements 11.4, 11.5
"""

import ipaddress
import tempfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.ip_sentinel.batch import BatchProcessor
from src.ip_sentinel.analyzer import IPAnalyzer
from src.ip_sentinel.config import Config


# Strategy for generating valid CIDR notations
@st.composite
def cidr_networks(draw, v=None):
    """Generate valid CIDR network notations."""
    if v is None:
        v = draw(st.sampled_from([4, 6]))

    if v == 4:
        # Generate IPv4 CIDR (e.g., 192.168.1.0/24)
        # Use prefix lengths that generate reasonable numbers of IPs
        prefix_len = draw(st.integers(min_value=24, max_value=32))
        ip = draw(st.ip_addresses(v=4))
        network = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
        return str(network)
    else:
        # Generate IPv6 CIDR (e.g., 2001:db8::/64)
        # Use prefix lengths that generate reasonable numbers of IPs
        prefix_len = draw(st.integers(min_value=120, max_value=128))
        ip = draw(st.ip_addresses(v=6))
        network = ipaddress.IPv6Network(f"{ip}/{prefix_len}", strict=False)
        return str(network)


class TestCIDRExpansionAccuracy:
    """Property tests for CIDR expansion accuracy."""

    @given(cidr_networks(v=4))
    @settings(max_examples=100, deadline=None)
    def test_ipv4_cidr_expansion_matches_standard_library(self, cidr):
        """
        Property 24: CIDR Expansion Accuracy
        For any valid IPv4 CIDR notation, expansion should match Python's ipaddress module.
        **Validates: Requirements 11.4, 11.5**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format='json',
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer and batch processor
            analyzer = IPAnalyzer(config)
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            # Expand using batch processor
            expanded_ips = batch_processor.expand_cidr(cidr)

            # Expand using standard library
            network = ipaddress.ip_network(cidr, strict=False)
            expected_ips = list(network.hosts())

            # For /31 and /32 networks, hosts() returns empty, use all addresses
            if not expected_ips:
                expected_ips = list(network)

            # Should match exactly
            assert len(expanded_ips) == len(expected_ips)
            assert set(expanded_ips) == set(expected_ips)

            # Order should be preserved
            for i, ip in enumerate(expanded_ips):
                assert ip == expected_ips[i]

    @given(cidr_networks(v=6))
    @settings(max_examples=100, deadline=None)
    def test_ipv6_cidr_expansion_matches_standard_library(self, cidr):
        """
        Property 24: CIDR Expansion Accuracy
        For any valid IPv6 CIDR notation, expansion should match Python's ipaddress module.
        **Validates: Requirements 11.4, 11.5**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format='json',
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer and batch processor
            analyzer = IPAnalyzer(config)
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            # Expand using batch processor
            expanded_ips = batch_processor.expand_cidr(cidr)

            # Expand using standard library
            network = ipaddress.ip_network(cidr, strict=False)
            expected_ips = list(network.hosts())

            # For /127 and /128 networks, hosts() returns empty, use all addresses
            if not expected_ips:
                expected_ips = list(network)

            # Should match exactly
            assert len(expanded_ips) == len(expected_ips)
            assert set(expanded_ips) == set(expected_ips)

            # Order should be preserved
            for i, ip in enumerate(expanded_ips):
                assert ip == expected_ips[i]

    @given(cidr_networks())
    @settings(max_examples=100, deadline=None)
    def test_cidr_expansion_produces_valid_ip_objects(self, cidr):
        """
        Property 24: CIDR Expansion Accuracy
        For any valid CIDR notation, all expanded IPs should be valid IP address objects.
        **Validates: Requirements 11.4, 11.5**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format='json',
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer and batch processor
            analyzer = IPAnalyzer(config)
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            # Expand CIDR
            expanded_ips = batch_processor.expand_cidr(cidr)

            # All should be valid IP address objects
            for ip in expanded_ips:
                assert isinstance(
                    ip, (ipaddress.IPv4Address, ipaddress.IPv6Address))
                # Should be convertible to string
                assert isinstance(str(ip), str)
                # Should be parseable back to IP
                reparsed = ipaddress.ip_address(str(ip))
                assert reparsed == ip

    @given(cidr_networks())
    @settings(max_examples=100, deadline=None)
    def test_cidr_expansion_all_ips_within_network(self, cidr):
        """
        Property 24: CIDR Expansion Accuracy
        For any valid CIDR notation, all expanded IPs should be within the network range.
        **Validates: Requirements 11.4, 11.5**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format='json',
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer and batch processor
            analyzer = IPAnalyzer(config)
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            # Expand CIDR
            expanded_ips = batch_processor.expand_cidr(cidr)

            # Get network object
            network = ipaddress.ip_network(cidr, strict=False)

            # All IPs should be within the network
            for ip in expanded_ips:
                assert ip in network

    @given(
        st.one_of(
            st.just("not.a.cidr"),
            st.just("192.168.1.0/33"),  # Invalid prefix
            st.just("256.1.1.0/24"),  # Invalid IP
            st.just("2001:db8::/129"),  # Invalid IPv6 prefix
            st.just("invalid/24"),
            st.just("999.999.999.999/24"),
            st.just("gggg::1/64"),
        )
    )
    @settings(max_examples=100, deadline=None)
    def test_invalid_cidr_notation_raises_error(self, invalid_cidr):
        """
        Property 24: CIDR Expansion Accuracy
        For any invalid CIDR notation, expansion should raise ValueError with clear message.
        **Validates: Requirements 11.4, 11.5**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format='json',
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer and batch processor
            analyzer = IPAnalyzer(config)
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            # Should raise ValueError
            with pytest.raises(ValueError) as exc_info:
                batch_processor.expand_cidr(invalid_cidr)

            # Error message should mention CIDR or invalid
            error_msg = str(exc_info.value).lower()
            assert 'cidr' in error_msg or 'invalid' in error_msg

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_single_ip_treated_as_host_network(self, ip):
        """
        Property 24: CIDR Expansion Accuracy
        For any single IP address without prefix, it should be treated as /32 or /128 network.
        **Validates: Requirements 11.4, 11.5**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format='json',
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer and batch processor
            analyzer = IPAnalyzer(config)
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            # Expand single IP (treated as /32 or /128)
            ip_str = str(ip)
            expanded_ips = batch_processor.expand_cidr(ip_str)

            # Should return single IP
            assert len(expanded_ips) == 1
            assert expanded_ips[0] == ip

    @given(cidr_networks())
    @settings(max_examples=100, deadline=None)
    def test_cidr_expansion_no_duplicates(self, cidr):
        """
        Property 24: CIDR Expansion Accuracy
        For any valid CIDR notation, expansion should produce no duplicate IPs.
        **Validates: Requirements 11.4, 11.5**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format='json',
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer and batch processor
            analyzer = IPAnalyzer(config)
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            # Expand CIDR
            expanded_ips = batch_processor.expand_cidr(cidr)

            # Should have no duplicates
            assert len(expanded_ips) == len(set(expanded_ips))

    @given(cidr_networks())
    @settings(max_examples=100, deadline=None)
    def test_cidr_expansion_consistent_version(self, cidr):
        """
        Property 24: CIDR Expansion Accuracy
        For any valid CIDR notation, all expanded IPs should have same version as network.
        **Validates: Requirements 11.4, 11.5**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format='json',
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer and batch processor
            analyzer = IPAnalyzer(config)
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            # Expand CIDR
            expanded_ips = batch_processor.expand_cidr(cidr)

            # Get network version
            network = ipaddress.ip_network(cidr, strict=False)
            expected_version = network.version

            # All IPs should have same version
            for ip in expanded_ips:
                assert ip.version == expected_version
