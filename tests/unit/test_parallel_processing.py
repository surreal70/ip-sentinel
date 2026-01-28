"""
Unit tests for parallel processing functionality.

Tests concurrent IP processing with multiple threads, thread-safe progress
updates, file writing without race conditions, and error handling in parallel mode.

Validates: Requirements 11.13, 11.14, 11.15
"""

import pytest
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from ipaddress import IPv4Address
from src.ip_sentinel.batch import BatchProcessor, ProgressTracker, FileOutputManager


class TestParallelProcessingBasics:
    """Test basic parallel processing functionality."""

    def test_parallel_mode_initialization(self):
        """Test that parallel mode is properly initialized."""
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

        with tempfile.TemporaryDirectory() as temp_dir:
            processor = BatchProcessor(
                analyzer=mock_analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=True
            )

            assert processor.parallel is True

    def test_sequential_mode_initialization(self):
        """Test that sequential mode is properly initialized."""
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

        with tempfile.TemporaryDirectory() as temp_dir:
            processor = BatchProcessor(
                analyzer=mock_analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            assert processor.parallel is False


class TestConcurrentIPProcessing:
    """Test concurrent IP processing with multiple threads."""

    def test_parallel_processing_multiple_ips(self):
        """Test processing multiple IPs in parallel."""
        # Create mock analyzer
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

        # Track which IPs were processed
        processed_ips = []
        lock = threading.Lock()

        def mock_analyze(ip_str):
            with lock:
                processed_ips.append(ip_str)
            result = Mock()
            result.ip_address = ip_str
            result.classifications = []
            result.local_info = None
            result.internet_info = None
            result.application_info = {}
            result.errors = []
            return result

        mock_analyzer.analyze = mock_analyze

        # Create test IPs
        test_ips = [
            IPv4Address('192.168.1.1'),
            IPv4Address('192.168.1.2'),
            IPv4Address('192.168.1.3'),
            IPv4Address('192.168.1.4'),
            IPv4Address('192.168.1.5')
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
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

            # Process IPs
            result = processor.process_ip_list(test_ips)

            # Verify all IPs were processed
            assert result.total_ips == len(test_ips)
            assert result.successful == len(test_ips)
            assert result.failed == 0

            # Verify all IPs were analyzed
            assert len(processed_ips) == len(test_ips)
            for ip in test_ips:
                assert str(ip) in processed_ips

    def test_parallel_processing_with_failures(self):
        """Test parallel processing when some IPs fail."""
        # Create mock analyzer that fails for specific IPs
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

        def mock_analyze(ip_str):
            # Fail for .2 and .4
            if ip_str.endswith('.2') or ip_str.endswith('.4'):
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

        # Create test IPs
        test_ips = [
            IPv4Address('192.168.1.1'),
            IPv4Address('192.168.1.2'),  # Will fail
            IPv4Address('192.168.1.3'),
            IPv4Address('192.168.1.4'),  # Will fail
            IPv4Address('192.168.1.5')
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
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

            # Process IPs
            result = processor.process_ip_list(test_ips)

            # Verify results
            assert result.total_ips == 5
            assert result.successful == 3
            assert result.failed == 2

            # Verify error tracking
            assert '192.168.1.2' in result.errors
            assert '192.168.1.4' in result.errors
            assert '192.168.1.1' not in result.errors


class TestThreadSafeProgressUpdates:
    """Test thread-safe progress updates."""

    def test_progress_tracker_parallel_mode_has_lock(self):
        """Test that parallel mode creates a lock."""
        tracker = ProgressTracker(total_ips=10, parallel=True)
        assert tracker._lock is not None

    def test_progress_tracker_sequential_mode_no_lock(self):
        """Test that sequential mode doesn't create a lock."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        assert tracker._lock is None

    def test_concurrent_progress_updates(self):
        """Test concurrent progress updates from multiple threads."""
        tracker = ProgressTracker(total_ips=10, parallel=True)

        errors = []

        def update_progress(idx):
            try:
                for _ in range(10):
                    tracker.update_overall_progress(idx, f"192.168.1.{idx}")
            except Exception as e:
                errors.append(e)

        # Create threads
        threads = []
        for i in range(1, 6):
            thread = threading.Thread(target=update_progress, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify no errors occurred
        assert len(errors) == 0


class TestThreadSafeFileWriting:
    """Test thread-safe file writing operations."""

    def test_file_output_manager_has_write_lock(self):
        """Test that FileOutputManager creates a write lock."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = FileOutputManager(temp_dir, 'json')
            assert manager._write_lock is not None

    def test_concurrent_file_writes(self):
        """Test concurrent file writes from multiple threads."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = FileOutputManager(temp_dir, 'json')
            manager.create_output_folder()

            errors = []
            written_files = []
            lock = threading.Lock()

            def write_file(ip_num):
                try:
                    ip = IPv4Address(f'192.168.1.{ip_num}')
                    content = f'{{"ip": "{ip}", "data": "test"}}'
                    manager.write_result(ip, content)
                    with lock:
                        written_files.append(str(manager.get_output_path(ip)))
                except Exception as e:
                    errors.append(e)

            # Create threads
            threads = []
            for i in range(1, 11):
                thread = threading.Thread(target=write_file, args=(i,))
                threads.append(thread)
                thread.start()

            # Wait for completion
            for thread in threads:
                thread.join()

            # Verify no errors
            assert len(errors) == 0

            # Verify all files were written
            assert len(written_files) == 10

            # Verify all files exist and are readable
            for file_path in written_files:
                assert Path(file_path).exists()
                content = Path(file_path).read_text()
                assert '"ip"' in content

    def test_concurrent_writes_no_corruption(self):
        """Test that concurrent writes don't corrupt file content."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = FileOutputManager(temp_dir, 'json')
            manager.create_output_folder()

            def write_file(ip_num):
                ip = IPv4Address(f'192.168.1.{ip_num}')
                # Write a specific pattern
                content = f'{{"ip": "{ip}", "number": {ip_num}}}'
                manager.write_result(ip, content)

            # Create threads
            threads = []
            for i in range(1, 21):
                thread = threading.Thread(target=write_file, args=(i,))
                threads.append(thread)
                thread.start()

            # Wait for completion
            for thread in threads:
                thread.join()

            # Verify all files have correct content
            for i in range(1, 21):
                ip = IPv4Address(f'192.168.1.{i}')
                file_path = manager.get_output_path(ip)
                assert file_path.exists()

                content = file_path.read_text()
                assert f'"ip": "192.168.1.{i}"' in content
                assert f'"number": {i}' in content


class TestErrorHandlingParallelMode:
    """Test error handling in parallel mode."""

    def test_error_isolation_between_threads(self):
        """Test that errors in one thread don't affect others."""
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

        # Make analyzer fail for specific IPs
        def mock_analyze(ip_str):
            if ip_str == '192.168.1.2':
                raise Exception("Simulated error")

            result = Mock()
            result.ip_address = ip_str
            result.classifications = []
            result.local_info = None
            result.internet_info = None
            result.application_info = {}
            result.errors = []
            return result

        mock_analyzer.analyze = mock_analyze

        test_ips = [
            IPv4Address('192.168.1.1'),
            IPv4Address('192.168.1.2'),  # Will fail
            IPv4Address('192.168.1.3')
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
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

            # Process IPs
            result = processor.process_ip_list(test_ips)

            # Verify error isolation
            assert result.successful == 2
            assert result.failed == 1
            assert '192.168.1.2' in result.errors
            assert '192.168.1.1' in result.results
            assert '192.168.1.3' in result.results

    def test_all_failures_handled_gracefully(self):
        """Test that all failures are handled gracefully."""
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

        # Make all analyses fail
        def mock_analyze(ip_str):
            raise Exception(f"Simulated failure for {ip_str}")

        mock_analyzer.analyze = mock_analyze

        test_ips = [
            IPv4Address('192.168.1.1'),
            IPv4Address('192.168.1.2'),
            IPv4Address('192.168.1.3')
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
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

            # Process IPs
            result = processor.process_ip_list(test_ips)

            # Verify all failed
            assert result.successful == 0
            assert result.failed == 3
            assert len(result.errors) == 3


class TestWorkerThreadPoolManagement:
    """Test worker thread pool management."""

    @patch('os.cpu_count', return_value=8)
    def test_worker_count_based_on_cpu(self, mock_cpu_count):
        """Test that worker count is based on CPU count."""
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

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

        # Create more IPs than max workers
        test_ips = [IPv4Address(f'192.168.1.{i}') for i in range(1, 16)]

        with tempfile.TemporaryDirectory() as temp_dir:
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

            # Process IPs
            result = processor.process_ip_list(test_ips)

            # Verify all processed successfully
            assert result.successful == 15
            assert result.failed == 0

    def test_worker_count_limited_to_max(self):
        """Test that worker count is limited to maximum."""
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

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

        # Create small number of IPs
        test_ips = [IPv4Address(f'192.168.1.{i}') for i in range(1, 4)]

        with tempfile.TemporaryDirectory() as temp_dir:
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

            # Process IPs
            result = processor.process_ip_list(test_ips)

            # Verify all processed successfully
            assert result.successful == 3
            assert result.failed == 0


class TestParallelVsSequentialComparison:
    """Test comparison between parallel and sequential modes."""

    def test_parallel_and_sequential_produce_same_results(self):
        """Test that parallel and sequential modes produce same results."""
        # Create mock analyzer
        mock_analyzer = Mock()
        mock_config = Mock()
        mock_config.reporting_mode = 'dense'
        mock_analyzer.config = mock_config

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

        test_ips = [IPv4Address(f'192.168.1.{i}') for i in range(1, 6)]

        # Process in sequential mode
        with tempfile.TemporaryDirectory() as temp_dir:
            processor_seq = BatchProcessor(
                analyzer=mock_analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=False
            )

            def mock_get_formatter():
                formatter = Mock()
                formatter.format_result = lambda r: f'{{"ip": "{r.ip_address}"}}'
                return formatter

            processor_seq._get_formatter = mock_get_formatter
            result_seq = processor_seq.process_ip_list(test_ips)

        # Process in parallel mode
        with tempfile.TemporaryDirectory() as temp_dir:
            processor_par = BatchProcessor(
                analyzer=mock_analyzer,
                output_folder=temp_dir,
                format_type='json',
                parallel=True
            )

            processor_par._get_formatter = mock_get_formatter
            result_par = processor_par.process_ip_list(test_ips)

        # Verify same results
        assert result_seq.total_ips == result_par.total_ips
        assert result_seq.successful == result_par.successful
        assert result_seq.failed == result_par.failed
        assert len(result_seq.results) == len(result_par.results)
        assert len(result_seq.errors) == len(result_par.errors)
