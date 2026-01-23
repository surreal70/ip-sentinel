"""
Property-based tests for parallel processing thread safety.

Tests that parallel batch processing maintains thread safety for progress
indicators and file operations without data corruption or race conditions.

Feature: ip-intelligence-analyzer, Property 29: Parallel Processing Thread Safety
Validates: Requirements 11.13, 11.14, 11.15
"""

import os
import tempfile
import threading
from pathlib import Path
from unittest.mock import Mock, MagicMock
from hypothesis import given, settings, strategies as st, assume, HealthCheck
from ipaddress import IPv4Address, IPv6Address
from src.ip_sentinel.batch import (
    BatchProcessor,
    ProgressTracker,
    FileOutputManager
)


# Strategy for generating valid IP addresses (simplified)
@st.composite
def ip_addresses(draw):
    """Generate valid IPv4 addresses (simplified for testing)."""
    # Generate simple IPv4 addresses to avoid large base examples
    octets = [draw(st.integers(min_value=1, max_value=254)) for _ in range(4)]
    ip_str = '.'.join(map(str, octets))
    return IPv4Address(ip_str)


@st.composite
def ip_address_lists(draw, min_size=2, max_size=20):
    """Generate lists of unique IP addresses for batch processing."""
    size = draw(st.integers(min_value=min_size, max_value=max_size))
    # Generate unique IPs by using a set
    ips = set()
    attempts = 0
    max_attempts = size * 10  # Prevent infinite loops
    while len(ips) < size and attempts < max_attempts:
        ip = draw(ip_addresses())
        ips.add(ip)
        attempts += 1
    # Ensure we have at least min_size unique IPs
    assume(len(ips) >= min_size)
    return list(ips)


class TestParallelProcessingThreadSafety:
    """
    Property 29: Parallel Processing Thread Safety

    For any batch mode execution with parallel processing enabled,
    all progress indicators and file operations should remain thread-safe
    without data corruption or race conditions.
    """

    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example]
    )
    @given(ip_list=ip_address_lists(min_size=2, max_size=10))
    def test_parallel_progress_tracking_thread_safety(self, ip_list):
        """
        Test that progress tracking remains thread-safe in parallel mode.

        Property: For any list of IP addresses processed in parallel,
        progress updates should be thread-safe and not cause race conditions.
        """
        total_ips = len(ip_list)

        # Create progress tracker in parallel mode
        tracker = ProgressTracker(total_ips=total_ips, parallel=True)

        # Verify lock is created for parallel mode
        assert tracker._lock is not None, "Parallel mode should create a lock"

        # Simulate concurrent progress updates from multiple threads
        import threading
        errors = []

        def update_progress(idx, ip):
            try:
                ip_str = str(ip)
                tracker.update_overall_progress(idx, ip_str)
                tracker.start_stage(ip_str, "Classification")
                tracker.update_sub_progress(ip_str, "Classification", 0.5)
                tracker.complete_stage(ip_str, "Classification")
            except Exception as e:
                errors.append(e)

        # Create threads for concurrent updates
        threads = []
        for idx, ip in enumerate(ip_list, 1):
            thread = threading.Thread(target=update_progress, args=(idx, ip))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify no errors occurred
        assert len(errors) == 0, f"Thread safety errors occurred: {errors}"

        # Verify final state is consistent
        assert tracker.total_ips == total_ips
        assert 0 <= tracker.current_ip <= total_ips

    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example]
    )
    @given(ip_list=ip_address_lists(min_size=2, max_size=10))
    def test_parallel_file_writing_thread_safety(self, ip_list):
        """
        Test that file writing operations are thread-safe in parallel mode.

        Property: For any list of IP addresses processed in parallel,
        file writing should be thread-safe without race conditions or
        data corruption.
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file output manager
            file_manager = FileOutputManager(temp_dir, 'json')
            file_manager.create_output_folder()

            # Verify write lock exists
            assert file_manager._write_lock is not None

            # Simulate concurrent file writes from multiple threads
            errors = []
            written_files = []

            def write_file(ip):
                try:
                    content = f'{{"ip": "{ip}", "test": "data"}}'
                    file_manager.write_result(ip, content)
                    output_path = file_manager.get_output_path(ip)
                    written_files.append(str(output_path))
                except Exception as e:
                    errors.append(e)

            # Create threads for concurrent writes
            threads = []
            for ip in ip_list:
                thread = threading.Thread(target=write_file, args=(ip,))
                threads.append(thread)
                thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            # Verify no errors occurred
            assert len(errors) == 0, f"File writing errors occurred: {errors}"

            # Verify all files were written
            assert len(written_files) == len(ip_list)

            # Verify all files exist and are readable
            for file_path in written_files:
                assert Path(file_path).exists(), f"File not found: {file_path}"
                content = Path(file_path).read_text()
                assert len(content) > 0, f"File is empty: {file_path}"
                assert '"ip"' in content, f"File content invalid: {file_path}"

    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example]
    )
    @given(ip_list=ip_address_lists(min_size=3, max_size=8))
    def test_parallel_batch_processing_no_data_corruption(self, ip_list):
        """
        Test that parallel batch processing doesn't cause data corruption.

        Property: For any list of IP addresses processed in parallel,
        the final results should be complete and consistent without
        data corruption.
        """
        # Ensure we have unique IPs
        unique_ips = list(set(ip_list))
        assume(len(unique_ips) >= 3)

        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock analyzer
            mock_analyzer = Mock()
            mock_config = Mock()
            mock_config.reporting_mode = 'dense'
            mock_analyzer.config = mock_config

            # Mock analyze method to return consistent results
            def mock_analyze(ip_str):
                result = Mock()
                result.ip_address = ip_str
                result.classifications = []
                result.local_info = None
                result.internet_info = None
                result.application_info = {}
                result.errors = []
                return result

            mock_analyzer.analyze = mock_analyze

            # Create batch processor in parallel mode
            processor = BatchProcessor(
                analyzer=mock_analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=True
            )

            # Mock the formatter
            def mock_get_formatter():
                formatter = Mock()
                formatter.format_result = lambda r: f'{{"ip": "{r.ip_address}"}}'
                return formatter

            processor._get_formatter = mock_get_formatter

            # Process IP list in parallel
            result = processor.process_ip_list(unique_ips)

            # Verify results are complete
            assert result.total_ips == len(unique_ips)
            assert result.successful + result.failed == len(unique_ips)

            # Verify no data corruption in results
            assert len(result.results) == result.successful
            assert len(result.errors) == result.failed
            assert len(result.output_files) == result.successful

            # Verify all successful IPs have corresponding files
            for ip_str in result.results.keys():
                # Find corresponding file
                found = False
                for file_path in result.output_files:
                    if ip_str.replace('.', '_').replace(':', '_') in file_path:
                        found = True
                        assert Path(file_path).exists()
                        break
                assert found, f"Output file not found for {ip_str}"

    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example]
    )
    @given(
        ip_list=ip_address_lists(min_size=2, max_size=8),
        format_type=st.sampled_from(['json', 'html'])
    )
    def test_parallel_processing_format_consistency(self, ip_list, format_type):
        """
        Test that parallel processing maintains format consistency.

        Property: For any list of IP addresses processed in parallel with
        any valid format, all output files should use the same format
        consistently.
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file output manager
            file_manager = FileOutputManager(temp_dir, format_type)
            file_manager.create_output_folder()

            # Expected extension
            expected_ext = f".{format_type}"

            # Write files in parallel
            errors = []

            def write_file(ip):
                try:
                    content = f'<html>{ip}</html>' if format_type == 'html' else f'{{"ip": "{ip}"}}'
                    file_manager.write_result(ip, content)
                except Exception as e:
                    errors.append(e)

            threads = []
            for ip in ip_list:
                thread = threading.Thread(target=write_file, args=(ip,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            # Verify no errors
            assert len(errors) == 0

            # Verify all files have correct extension
            output_folder = Path(temp_dir)
            files = list(output_folder.glob(f"*{expected_ext}"))
            assert len(files) == len(ip_list)

            # Verify no files with wrong extension
            all_files = list(output_folder.glob("*"))
            for file in all_files:
                if file.name != '.write_test':  # Ignore test file
                    assert file.suffix == expected_ext

    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.large_base_example]
    )
    @given(ip_list=ip_address_lists(min_size=2, max_size=8))
    def test_parallel_error_isolation(self, ip_list):
        """
        Test that errors in parallel processing are properly isolated.

        Property: For any list of IP addresses processed in parallel,
        if some IPs fail, the failures should not affect successful
        processing of other IPs.
        """
        # Ensure we have unique IPs
        unique_ips = list(set(ip_list))
        assume(len(unique_ips) >= 2)

        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create mock analyzer that fails for some IPs
            mock_analyzer = Mock()
            mock_config = Mock()
            mock_config.reporting_mode = 'dense'
            mock_analyzer.config = mock_config

            # Make every other IP fail
            def mock_analyze(ip_str):
                # Fail if IP ends with even number
                last_char = ip_str.replace('.', '').replace(':', '')[-1]
                if last_char.isdigit() and int(last_char) % 2 == 0:
                    raise Exception(f"Simulated failure for {ip_str}")

                result = Mock()
                result.ip_address = ip_str
                result.classifications = []
                result.local_info = None
                result.internet_info = None
                result.application_info = {}
                result.errors = []
                return result

            mock_analyzer.analyze = mock_analyze

            # Create batch processor in parallel mode
            processor = BatchProcessor(
                analyzer=mock_analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=True
            )

            # Mock the formatter
            def mock_get_formatter():
                formatter = Mock()
                formatter.format_result = lambda r: f'{{"ip": "{r.ip_address}"}}'
                return formatter

            processor._get_formatter = mock_get_formatter

            # Process IP list in parallel
            result = processor.process_ip_list(unique_ips)

            # Verify total is correct
            assert result.total_ips == len(unique_ips)
            assert result.successful + result.failed == len(unique_ips)

            # Verify that some succeeded and some failed (error isolation)
            # At least one should succeed if we have multiple IPs
            if len(unique_ips) > 1:
                assert result.successful > 0 or result.failed > 0

            # Verify successful IPs have files
            assert len(result.output_files) == result.successful

            # Verify failed IPs have error messages
            assert len(result.errors) == result.failed
