"""
Property-based tests for batch size limit enforcement.

Feature: ip-intelligence-analyzer, Property 25: Batch Size Limit Enforcement
Validates: Requirements 11.6, 11.7
"""

import ipaddress
import tempfile

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from src.ip_sentinel.batch import (
    BatchProcessor,
    BatchSizeExceededError
)
from src.ip_sentinel.analyzer import IPAnalyzer
from src.ip_sentinel.config import Config


class TestBatchSizeLimitEnforcement:
    """Property tests for batch size limit enforcement."""

    @given(st.integers(min_value=24, max_value=32))
    @settings(max_examples=100, deadline=None)
    def test_ipv4_networks_within_limit_accepted(self, prefix_len):
        """
        Property 25: Batch Size Limit Enforcement
        For any IPv4 CIDR that expands to <= 1024 IPs, batch processing should proceed.
        **Validates: Requirements 11.6, 11.7**
        """
        # Calculate expected size
        network_size = 2 ** (32 - prefix_len)

        # Skip if network is too large
        assume(network_size <= 1024)

        # Create a test CIDR
        cidr = f"192.168.0.0/{prefix_len}"

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
            ip_list = batch_processor.expand_cidr(cidr)

            # Should not raise BatchSizeExceededError
            try:
                batch_processor.validate_batch_size(ip_list)
            except BatchSizeExceededError:
                pytest.fail(
                    f"Batch size {len(ip_list)} should be accepted (limit: 1024)")

            # Validation should return True
            assert batch_processor.validate_batch_size(ip_list) is True

    @given(st.integers(min_value=14, max_value=21))
    @settings(max_examples=100, deadline=None)
    def test_ipv4_networks_exceeding_limit_rejected(self, prefix_len):
        """
        Property 25: Batch Size Limit Enforcement
        For any IPv4 CIDR that expands to > 1024 IPs, batch processing should be rejected.
        **Validates: Requirements 11.6, 11.7**
        """
        # Calculate expected size
        network_size = 2 ** (32 - prefix_len)

        # Skip if network is within limit
        assume(network_size > 1024)

        # Create a test CIDR
        cidr = f"10.0.0.0/{prefix_len}"

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
            ip_list = batch_processor.expand_cidr(cidr)

            # Should raise BatchSizeExceededError
            with pytest.raises(BatchSizeExceededError) as exc_info:
                batch_processor.validate_batch_size(ip_list)

            # Error message should mention the limit
            error_msg = str(exc_info.value)
            assert '1024' in error_msg
            assert str(len(ip_list)) in error_msg

    @given(st.integers(min_value=120, max_value=128))
    @settings(max_examples=100, deadline=None)
    def test_ipv6_networks_within_limit_accepted(self, prefix_len):
        """
        Property 25: Batch Size Limit Enforcement
        For any IPv6 CIDR that expands to <= 1024 IPs, batch processing should proceed.
        **Validates: Requirements 11.6, 11.7**
        """
        # Calculate expected size
        network_size = 2 ** (128 - prefix_len)

        # Skip if network is too large
        assume(network_size <= 1024)

        # Create a test CIDR
        cidr = f"2001:db8::/{prefix_len}"

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
            ip_list = batch_processor.expand_cidr(cidr)

            # Should not raise BatchSizeExceededError
            try:
                batch_processor.validate_batch_size(ip_list)
            except BatchSizeExceededError:
                pytest.fail(
                    f"Batch size {len(ip_list)} should be accepted (limit: 1024)")

            # Validation should return True
            assert batch_processor.validate_batch_size(ip_list) is True

    @given(st.integers(min_value=110, max_value=117))
    @settings(max_examples=100, deadline=None)
    def test_ipv6_networks_exceeding_limit_rejected(self, prefix_len):
        """
        Property 25: Batch Size Limit Enforcement
        For any IPv6 CIDR that expands to > 1024 IPs, batch processing should be rejected.
        **Validates: Requirements 11.6, 11.7**
        """
        # Calculate expected size
        network_size = 2 ** (128 - prefix_len)

        # Skip if network is within limit
        assume(network_size > 1024)

        # Create a test CIDR
        cidr = f"2001:db8::/{prefix_len}"

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
            ip_list = batch_processor.expand_cidr(cidr)

            # Should raise BatchSizeExceededError
            with pytest.raises(BatchSizeExceededError) as exc_info:
                batch_processor.validate_batch_size(ip_list)

            # Error message should mention the limit
            error_msg = str(exc_info.value)
            assert '1024' in error_msg
            assert str(len(ip_list)) in error_msg

    @given(st.integers(min_value=1, max_value=1024))
    @settings(max_examples=100, deadline=None)
    def test_exact_and_below_limit_accepted(self, list_size):
        """
        Property 25: Batch Size Limit Enforcement
        For any IP list with size <= 1024, validation should succeed.
        **Validates: Requirements 11.6, 11.7**
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

            # Create IP list of specified size
            ip_list = [ipaddress.IPv4Address(f"192.168.{i // 256}.{i % 256}")
                       for i in range(list_size)]

            # Should not raise exception
            result = batch_processor.validate_batch_size(ip_list)
            assert result is True

    @given(st.integers(min_value=1025, max_value=5000))
    @settings(max_examples=100, deadline=None)
    def test_above_limit_rejected(self, list_size):
        """
        Property 25: Batch Size Limit Enforcement
        For any IP list with size > 1024, validation should fail with clear error.
        **Validates: Requirements 11.6, 11.7**
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

            # Create IP list of specified size
            ip_list = [
                ipaddress.IPv4Address(
                    f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}")
                for i in range(list_size)
            ]

            # Should raise BatchSizeExceededError
            with pytest.raises(BatchSizeExceededError) as exc_info:
                batch_processor.validate_batch_size(ip_list)

            # Error message should be descriptive
            error_msg = str(exc_info.value)
            assert '1024' in error_msg
            assert str(list_size) in error_msg
            assert 'exceed' in error_msg.lower()

    def test_exactly_1024_ips_accepted(self):
        """
        Property 25: Batch Size Limit Enforcement
        For exactly 1024 IPs (the limit), validation should succeed.
        **Validates: Requirements 11.6, 11.7**
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

            # Create exactly 1024 IPs
            ip_list = [ipaddress.IPv4Address(f"192.168.{i // 256}.{i % 256}")
                       for i in range(1024)]

            # Should not raise exception
            result = batch_processor.validate_batch_size(ip_list)
            assert result is True
            assert len(ip_list) == 1024

    def test_exactly_1025_ips_rejected(self):
        """
        Property 25: Batch Size Limit Enforcement
        For exactly 1025 IPs (one over limit), validation should fail.
        **Validates: Requirements 11.6, 11.7**
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

            # Create exactly 1025 IPs
            ip_list = [ipaddress.IPv4Address(f"192.168.{i // 256}.{i % 256}")
                       for i in range(1025)]

            # Should raise BatchSizeExceededError
            with pytest.raises(BatchSizeExceededError) as exc_info:
                batch_processor.validate_batch_size(ip_list)

            # Error message should mention 1025 and 1024
            error_msg = str(exc_info.value)
            assert '1024' in error_msg
            assert '1025' in error_msg
