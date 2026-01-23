"""
Integration tests for batch mode processing.

Tests batch mode with various CIDR networks, output formats, and error conditions.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from src.ip_sentinel.analyzer import IPAnalyzer
from src.ip_sentinel.batch import (
    BatchProcessor,
    BatchSizeExceededError,
    InvalidOutputFormatError,
    OutputFolderError
)
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


class TestBatchModeSmallNetworks:
    """Test batch mode with small CIDR networks."""

    def test_batch_mode_with_slash_29_network(
            self, test_analyzer, temp_output_folder):
        """Test batch mode with /29 network (6 usable hosts)."""
        # /29 network has 8 addresses, 6 usable hosts (excluding network and broadcast)
        cidr = "192.168.1.0/29"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify results
        assert result.total_ips == 6  # Usable hosts in /29
        assert result.successful >= 0
        assert result.failed >= 0
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

    def test_batch_mode_with_slash_28_network(
            self, test_analyzer, temp_output_folder):
        """Test batch mode with /28 network (14 usable hosts)."""
        cidr = "10.0.0.0/28"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify results
        assert result.total_ips == 14  # Usable hosts in /28
        assert result.successful + result.failed == result.total_ips

        # Verify output files
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful


class TestBatchModeMaximumSize:
    """Test batch mode with maximum allowed size."""

    def test_batch_mode_with_1024_ips(self, test_analyzer, temp_output_folder):
        """Test batch mode with exactly 1024 IP addresses."""
        # /22 network has 1024 addresses (1022 usable hosts)
        # We'll use a smaller network that expands to exactly 1024 or less
        # /22 = 1024 addresses total, but hosts() excludes network and broadcast
        # So we get 1022 usable hosts
        cidr = "172.16.0.0/22"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify results
        assert result.total_ips == 1022  # Usable hosts in /22
        assert result.total_ips <= 1024  # Within limit
        assert result.successful + result.failed == result.total_ips


class TestBatchModeSizeLimit:
    """Test batch mode size limit enforcement."""

    def test_batch_mode_rejects_exceeding_1024_limit(
            self, test_analyzer, temp_output_folder):
        """Test that batch mode rejects CIDR networks exceeding 1024 IPs."""
        # /21 network has 2048 addresses (2046 usable hosts) - exceeds limit
        cidr = "192.168.0.0/21"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        # Should raise BatchSizeExceededError
        with pytest.raises(BatchSizeExceededError) as exc_info:
            batch_processor.process_cidr(cidr)

        assert "exceeds maximum allowed limit" in str(exc_info.value)
        assert "1024" in str(exc_info.value)


class TestBatchModeOutputFormats:
    """Test batch mode with different output formats."""

    def test_batch_mode_with_json_format(
            self, test_analyzer, temp_output_folder):
        """Test batch mode with JSON output format."""
        cidr = "192.168.100.0/29"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify JSON files were created
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

        # Verify JSON content
        for output_file in output_files:
            with open(output_file, 'r') as f:
                data = json.load(f)
                assert isinstance(data, dict)
                assert 'ip_address' in data

    def test_batch_mode_with_html_format(
            self, test_analyzer, temp_output_folder):
        """Test batch mode with HTML output format."""
        cidr = "10.10.10.0/29"

        # Update config for HTML output
        test_analyzer.config.output_format = "html"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="html",
            parallel=False
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

    def test_batch_mode_rejects_human_format(self, test_analyzer, temp_output_folder):
        """Test that batch mode rejects human-readable format."""
        # Should raise InvalidOutputFormatError when trying to create
        # BatchProcessor with human format
        with pytest.raises(InvalidOutputFormatError) as exc_info:
            BatchProcessor(
                analyzer=test_analyzer,
                output_folder=temp_output_folder,
                format_type="human",
                parallel=False
            )

        assert "JSON or HTML" in str(exc_info.value)


class TestBatchModeOutputFolder:
    """Test batch mode output folder management."""

    def test_batch_mode_creates_output_folder(self, test_analyzer):
        """Test that batch mode creates output folder if it doesn't exist."""
        # Use a non-existent folder path
        temp_dir = tempfile.mkdtemp()
        output_folder = os.path.join(temp_dir, "batch_results", "test_run")

        try:
            batch_processor = BatchProcessor(
                analyzer=test_analyzer,
                output_folder=output_folder,
                format_type="json",
                parallel=False
            )

            # Process a small network
            cidr = "192.168.200.0/30"  # 2 usable hosts
            result = batch_processor.process_cidr(cidr)

            # Verify folder was created
            assert os.path.exists(output_folder)
            assert os.path.isdir(output_folder)

            # Verify files were written
            output_files = list(Path(output_folder).glob("*.json"))
            assert len(output_files) == result.successful

        finally:
            # Cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_batch_mode_uses_existing_output_folder(
            self, test_analyzer, temp_output_folder):
        """Test that batch mode uses existing output folder."""
        # Folder already exists (from fixture)
        assert os.path.exists(temp_output_folder)

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        cidr = "10.20.30.0/30"
        result = batch_processor.process_cidr(cidr)

        # Verify files were written to existing folder
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful


class TestBatchModeFilenameSanitization:
    """Test filename sanitization for IPv4 and IPv6 addresses."""

    def test_ipv4_filename_sanitization(
            self, test_analyzer, temp_output_folder):
        """Test that IPv4 addresses are sanitized correctly in filenames."""
        cidr = "192.168.1.0/30"  # 2 usable hosts: .1 and .2

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify filenames use underscores instead of dots
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

        for output_file in output_files:
            filename = output_file.name
            # IPv4 addresses should have underscores instead of dots
            assert '.' not in filename.replace('.json', '')
            assert '_' in filename

    def test_ipv6_filename_sanitization(
            self, test_analyzer, temp_output_folder):
        """Test that IPv6 addresses are sanitized correctly in filenames."""
        # Use a small IPv6 network
        cidr = "2001:db8::/126"  # 4 addresses

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify filenames use underscores instead of colons
        output_files = list(Path(temp_output_folder).glob("*.json"))
        assert len(output_files) == result.successful

        for output_file in output_files:
            filename = output_file.name
            # IPv6 addresses should have underscores instead of colons
            assert ':' not in filename
            assert '_' in filename


class TestBatchModeErrorHandling:
    """Test error handling in batch mode."""

    def test_batch_mode_handles_invalid_cidr(
            self, test_analyzer, temp_output_folder):
        """Test that batch mode handles invalid CIDR notation."""
        invalid_cidr = "not-a-valid-cidr"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        # Should raise ValueError for invalid CIDR
        with pytest.raises(ValueError) as exc_info:
            batch_processor.process_cidr(invalid_cidr)

        assert "Invalid CIDR notation" in str(exc_info.value)

    def test_batch_mode_continues_on_individual_failures(
            self, test_analyzer, temp_output_folder):
        """Test that batch mode continues processing even if some IPs fail."""
        # Use a small network
        cidr = "192.168.50.0/29"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Even if some IPs fail, the batch should complete
        assert result.total_ips > 0
        assert result.successful + result.failed == result.total_ips

        # Verify that successful results were written
        if result.successful > 0:
            output_files = list(Path(temp_output_folder).glob("*.json"))
            assert len(output_files) == result.successful


class TestBatchModeResultAggregation:
    """Test result aggregation and statistics in batch mode."""

    def test_batch_result_contains_statistics(
            self, test_analyzer, temp_output_folder):
        """Test that batch result contains correct statistics."""
        cidr = "172.20.0.0/29"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify result structure
        assert hasattr(result, 'total_ips')
        assert hasattr(result, 'successful')
        assert hasattr(result, 'failed')
        assert hasattr(result, 'start_time')
        assert hasattr(result, 'end_time')
        assert hasattr(result, 'results')
        assert hasattr(result, 'errors')
        assert hasattr(result, 'output_files')

        # Verify statistics
        assert result.total_ips > 0
        assert result.successful >= 0
        assert result.failed >= 0
        assert result.successful + result.failed == result.total_ips

        # Verify timing
        assert result.end_time >= result.start_time
        assert result.duration >= 0

    def test_batch_result_tracks_errors(
            self, test_analyzer, temp_output_folder):
        """Test that batch result tracks errors for failed IPs."""
        cidr = "10.50.0.0/29"

        batch_processor = BatchProcessor(
            analyzer=test_analyzer,
            output_folder=temp_output_folder,
            format_type="json",
            parallel=False
        )

        result = batch_processor.process_cidr(cidr)

        # Verify error tracking
        assert isinstance(result.errors, dict)

        # If there are failures, errors dict should have entries
        if result.failed > 0:
            assert len(result.errors) == result.failed
            # Each error should have an IP address key and error message value
            for ip_str, error_msg in result.errors.items():
                assert isinstance(ip_str, str)
                assert isinstance(error_msg, str)
                assert len(error_msg) > 0
