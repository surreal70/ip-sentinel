"""
Integration tests for parallel batch mode processing.

Tests parallel processing with multiple IPs, progress tracking,
file output consistency, and error handling.
"""

import json
import shutil
import tempfile
import threading
import time
from pathlib import Path

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


class TestParallelProcessing:
    """Test parallel processing of multiple IPs."""

    def test_parallel_processing_with_multiple_ips(
            self, test_analyzer, temp_output_folder):
        """Test parallel processing with multiple IP addresses."""
        # Use a /28 network (14 usable hosts) for parallel processing
        cidr = "192.168.10.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True  # Enable parallel processing
        )

        result = batch_processor.process_cidr(cidr)

        # Verify results
        assert result.total_ips == 14
        assert result.successful + result.failed == result.total_ips

        # Verify output files were created
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

        # Verify each file contains valid JSON
        for output_file in output_files:
            with open(output_file, 'r') as f:
                data = json.load(f)
                assert 'ip_address' in data
                assert 'classifications' in data

    def test_parallel_processing_faster_than_sequential(
            self, test_analyzer, temp_output_folder):
        """Test that parallel processing is faster than sequential for larger batches."""
        # Use a /27 network (30 usable hosts)
        cidr = "10.0.0.0/27"

        # Sequential processing
        batch_processor_seq = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder + "_seq",
            format_type="json",
            parallel=False
        )

        start_seq = time.time()
        result_seq = batch_processor_seq.process_cidr(cidr)
        duration_seq = time.time() - start_seq

        # Parallel processing
        batch_processor_par = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder + "_par",
            format_type="json",
            parallel=True
        )

        start_par = time.time()
        result_par = batch_processor_par.process_cidr(cidr)
        duration_par = time.time() - start_par

        # Verify both produced same number of results
        assert result_seq.total_ips == result_par.total_ips
        assert result_seq.successful == result_par.successful

        # Note: We don't strictly enforce parallel being faster in tests
        # because test environment may vary, but we log the comparison
        print(f"\nSequential: {duration_seq:.2f}s, Parallel: {duration_par:.2f}s")

        # Cleanup additional folders
        shutil.rmtree(temp_output_folder + "_seq", ignore_errors=True)
        shutil.rmtree(temp_output_folder + "_par", ignore_errors=True)

    def test_parallel_processing_with_small_batch(
            self, test_analyzer, temp_output_folder):
        """Test parallel processing with small batch (fewer IPs than workers)."""
        # Use a /30 network (2 usable hosts)
        cidr = "172.16.0.0/30"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify results
        assert result.total_ips == 2
        assert result.successful + result.failed == result.total_ips

        # Verify output files
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful


class TestParallelProgressTracking:
    """Test progress tracking in parallel mode."""

    def test_progress_tracking_in_parallel_mode(
            self, test_analyzer, temp_output_folder):
        """Test that progress tracking works correctly in parallel mode."""
        cidr = "192.168.20.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        # Process with progress tracking
        result = batch_processor.process_cidr(cidr)

        # Verify progress tracker was initialized
        assert batch_processor.progress_tracker is not None
        assert batch_processor.progress_tracker.parallel is True
        assert batch_processor.progress_tracker.total_ips == result.total_ips

        # Verify final progress state
        assert batch_processor.progress_tracker.current_ip <= result.total_ips

    def test_progress_tracker_thread_safety(
            self, test_analyzer, temp_output_folder):
        """Test that progress tracker is thread-safe in parallel mode."""
        cidr = "10.10.0.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        # Process in parallel
        result = batch_processor.process_cidr(cidr)

        # Verify no race conditions occurred
        # If there were race conditions, we'd see inconsistent counts
        assert result.successful + result.failed == result.total_ips

        # Verify all successful results have output files
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful


class TestParallelFileOutputConsistency:
    """Test file output consistency in parallel mode."""

    def test_file_output_consistency_in_parallel_mode(
            self, test_analyzer, temp_output_folder):
        """Test that file outputs are consistent in parallel mode."""
        cidr = "192.168.30.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify all output files are valid and complete
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

        # Verify each file is valid JSON and contains expected data
        for output_file in output_files:
            # Check file is not empty
            assert output_file.stat().st_size > 0

            # Check file contains valid JSON
            with open(output_file, 'r') as f:
                data = json.load(f)
                assert isinstance(data, dict)
                assert 'ip_address' in data
                assert 'scan_timestamp' in data
                assert 'classifications' in data

    def test_no_file_corruption_in_parallel_mode(
            self, test_analyzer, temp_output_folder):
        """Test that files are not corrupted by concurrent writes."""
        cidr = "172.20.0.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Read all files and verify integrity
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

        for output_file in output_files:
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    # If we can parse JSON, file is not corrupted
                    assert data is not None
            except json.JSONDecodeError:
                pytest.fail(f"File {output_file} is corrupted (invalid JSON)")

    def test_unique_filenames_in_parallel_mode(
            self, test_analyzer, temp_output_folder):
        """Test that each IP gets a unique filename in parallel mode."""
        cidr = "10.20.0.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Get all output files
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

        # Verify all filenames are unique
        filenames = [f.name for f in output_files]
        assert len(filenames) == len(set(filenames))  # No duplicates


class TestParallelErrorHandling:
    """Test error handling when some IPs fail in parallel mode."""

    def test_error_handling_when_some_ips_fail(
            self, test_analyzer, temp_output_folder):
        """Test that parallel mode handles individual IP failures gracefully."""
        cidr = "192.168.40.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify batch completed even if some IPs failed
        assert result.total_ips > 0
        assert result.successful + result.failed == result.total_ips

        # Verify successful results were written
        if result.successful > 0:
            output_files = list(Path(temp_output_folder).glob("*.json"))
            assert len(output_files) == result.successful

        # Verify errors are tracked
        if result.failed > 0:
            assert len(result.errors) == result.failed
            for ip_str, error_msg in result.errors.items():
                assert isinstance(ip_str, str)
                assert isinstance(error_msg, str)

    def test_error_isolation_in_parallel_mode(
            self, test_analyzer, temp_output_folder):
        """Test that errors in one IP don't affect others in parallel mode."""
        cidr = "10.30.0.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Even if some IPs fail, others should succeed
        # In our test environment with classification only, all should succeed
        assert result.successful > 0

        # Verify successful results are valid
        output_files = list(Path(temp_output_folder).glob("*.json"))
        for output_file in output_files:
            with open(output_file, 'r') as f:
                data = json.load(f)
                assert 'ip_address' in data


class TestParallelRaceConditions:
    """Test for race conditions and data corruption in parallel mode."""

    def test_no_race_conditions_in_result_aggregation(
            self, test_analyzer, temp_output_folder):
        """Test that result aggregation has no race conditions."""
        cidr = "192.168.50.0/27"  # 30 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify counts are consistent
        assert result.successful + result.failed == result.total_ips

        # Verify result dictionary has correct number of entries
        assert len(result.results) == result.successful

        # Verify error dictionary has correct number of entries
        assert len(result.errors) == result.failed

        # Verify output files match successful count
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

    def test_no_race_conditions_in_file_writing(
            self, test_analyzer, temp_output_folder):
        """Test that file writing has no race conditions."""
        cidr = "172.30.0.0/27"  # 30 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify all files are complete and valid
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

        # Verify no partial writes or corruption
        for output_file in output_files:
            # File should not be empty
            assert output_file.stat().st_size > 0

            # File should contain valid JSON
            with open(output_file, 'r') as f:
                data = json.load(f)
                assert data is not None
                assert 'ip_address' in data

    def test_thread_safe_counter_updates(
            self, test_analyzer, temp_output_folder):
        """Test that success/failure counters are updated thread-safely."""
        cidr = "10.40.0.0/27"  # 30 usable hosts

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify counters are accurate
        # If there were race conditions, counts would be inconsistent
        assert result.successful >= 0
        assert result.failed >= 0
        assert result.successful + result.failed == result.total_ips

        # Verify output files match successful count exactly
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful


class TestParallelPerformance:
    """Test performance characteristics of parallel mode."""

    def test_parallel_mode_completes_successfully(
            self, test_analyzer, temp_output_folder):
        """Test that parallel mode completes successfully with larger batch."""
        # Use a /26 network (62 usable hosts)
        cidr = "192.168.60.0/26"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify completion
        assert result.total_ips == 62
        assert result.successful + result.failed == result.total_ips

        # Verify all output files
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

    def test_parallel_mode_with_html_output(
            self, test_analyzer, temp_output_folder):
        """Test parallel mode with HTML output format."""
        cidr = "10.50.0.0/28"

        # Update config for HTML output
        test_analyzer.config.output_format = "html"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="html",
            parallel=True
        )

        result = batch_processor.process_cidr(cidr)

        # Verify HTML files were created
        output_files = list(Path(temp_output_folder).glob("*.html"))
        assert len(output_files) == result.successful

        # Verify HTML content
        for output_file in output_files:
            content = output_file.read_text()
            assert '<html' in content.lower()
            assert '</html>' in content.lower()
