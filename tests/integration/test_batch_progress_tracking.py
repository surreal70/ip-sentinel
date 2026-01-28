"""
Integration tests for BatchProcessor progress tracking.

Tests that BatchProcessor correctly integrates with ProgressTracker,
including completion counter updates for both successful and failed scans.
"""

import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.ip_sentinel.analyzer import IPAnalyzer
from src.ip_sentinel.batch import BatchProcessor
from src.ip_sentinel.config import Config, ConfigManager


@pytest.fixture
def temp_output_folder():
    """Create a temporary output folder for batch results."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    # Cleanup after test
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_config():
    """Create a test configuration."""
    return Config(
        database_path=None,
        output_format="json",
        reporting_mode="dense",
        force_internet=False,
        enabled_modules={
            "classification": True,
            "local_info": False,  # Disable to speed up tests
            "internet_info": False,  # Disable to speed up tests
            "netbox": False,
            "checkmk": False,
            "openitcockpit": False,
            "openvas": False,
            "infoblox": False,
        },
        run_root=False,
        verify_ssl=True,
        verbose=False
    )


@pytest.fixture
def test_analyzer(test_config):
    """Create a test analyzer instance."""
    config_manager = ConfigManager()
    return IPAnalyzer(config=test_config, config_manager=config_manager)


class TestSequentialProgressTracking:
    """Test progress tracking in sequential processing mode."""

    def test_sequential_processing_tracks_completion(
            self, test_analyzer, temp_output_folder):
        """Test that sequential processing tracks completion counter correctly."""
        cidr = "192.168.1.0/29"  # 6 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify completion counter matches total IPs processed
        assert batch_processor.progress_tracker.completed_scans == result.total_ips
        assert result.successful + result.failed == result.total_ips

    def test_sequential_processing_completion_matches_total(
            self, test_analyzer, temp_output_folder):
        """Test that completion counter equals total IPs after processing."""
        cidr = "10.0.0.0/30"  # 2 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # After processing, completed_scans should equal total_ips
        assert batch_processor.progress_tracker.completed_scans == result.total_ips
        assert batch_processor.progress_tracker.completed_scans == batch_processor.progress_tracker.total_ips


class TestParallelProgressTracking:
    """Test progress tracking in parallel processing mode."""

    def test_parallel_processing_tracks_completion(
            self, test_analyzer, temp_output_folder):
        """Test that parallel processing tracks completion counter correctly."""
        cidr = "192.168.2.0/29"  # 6 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify completion counter matches total IPs processed
        assert batch_processor.progress_tracker.completed_scans == result.total_ips
        assert result.successful + result.failed == result.total_ips

    def test_parallel_processing_completion_matches_total(
            self, test_analyzer, temp_output_folder):
        """Test that completion counter equals total IPs after parallel processing."""
        cidr = "10.1.0.0/30"  # 2 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # After processing, completed_scans should equal total_ips
        assert batch_processor.progress_tracker.completed_scans == result.total_ips
        assert batch_processor.progress_tracker.completed_scans == batch_processor.progress_tracker.total_ips


class TestFailureCompletionTracking:
    """Test that failures are counted in completion counter."""

    def test_sequential_failures_counted_in_completion(
            self, test_analyzer, temp_output_folder):
        """Test that failed scans are counted in completion counter (sequential)."""
        cidr = "192.168.3.0/30"  # 2 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        # Mock analyzer to force some failures
        original_analyze = batch_processor.analyzer.analyze
        call_count = [0]

        def mock_analyze(ip_str):
            call_count[0] += 1
            # Fail every other IP
            if call_count[0] % 2 == 0:
                raise Exception("Simulated failure")
            return original_analyze(ip_str)

        batch_processor.analyzer.analyze = mock_analyze

        result = batch_processor.process_cidr(cidr)

        # Verify completion counter includes both successes and failures
        assert batch_processor.progress_tracker.completed_scans == result.total_ips
        assert result.successful + result.failed == result.total_ips
        # At least one failure should have occurred
        assert result.failed > 0

    def test_parallel_failures_counted_in_completion(
            self, test_analyzer, temp_output_folder):
        """Test that failed scans are counted in completion counter (parallel)."""
        cidr = "192.168.4.0/30"  # 2 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        # Mock analyzer to force some failures
        original_analyze = batch_processor.analyzer.analyze
        call_count = [0]

        def mock_analyze(ip_str):
            call_count[0] += 1
            # Fail every other IP
            if call_count[0] % 2 == 0:
                raise Exception("Simulated failure")
            return original_analyze(ip_str)

        batch_processor.analyzer.analyze = mock_analyze

        result = batch_processor.process_cidr(cidr)

        # Verify completion counter includes both successes and failures
        assert batch_processor.progress_tracker.completed_scans == result.total_ips
        assert result.successful + result.failed == result.total_ips
        # At least one failure should have occurred
        assert result.failed > 0


class TestProgressTrackerInitialization:
    """Test that ProgressTracker is properly initialized."""

    def test_progress_tracker_initialized_with_correct_total(
            self, test_analyzer, temp_output_folder):
        """Test that ProgressTracker is initialized with correct total_ips."""
        cidr = "10.2.0.0/29"  # 6 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        # Before processing, progress_tracker should be None
        assert batch_processor.progress_tracker is None

        result = batch_processor.process_cidr(cidr)

        # After processing, progress_tracker should be initialized
        assert batch_processor.progress_tracker is not None
        assert batch_processor.progress_tracker.total_ips == result.total_ips

    def test_progress_tracker_parallel_mode_matches_processor(
            self, test_analyzer, temp_output_folder):
        """Test that ProgressTracker parallel mode matches BatchProcessor."""
        cidr = "10.3.0.0/30"  # 2 usable hosts

        # Test sequential mode
        batch_processor_seq = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )
        batch_processor_seq.process_cidr(cidr)
        assert batch_processor_seq.progress_tracker.parallel is False

        # Test parallel mode
        batch_processor_par = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )
        batch_processor_par.process_cidr(cidr)
        assert batch_processor_par.progress_tracker.parallel is True


class TestCompletionCounterBounds:
    """Test that completion counter respects bounds."""

    def test_completion_counter_never_exceeds_total(
            self, test_analyzer, temp_output_folder):
        """Test that completion counter never exceeds total_ips."""
        cidr = "192.168.5.0/30"  # 2 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Completion counter should never exceed total
        assert batch_processor.progress_tracker.completed_scans <= batch_processor.progress_tracker.total_ips
        assert batch_processor.progress_tracker.completed_scans == result.total_ips
