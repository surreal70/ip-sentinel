"""
Property-based tests for batch mode output format restriction.

Feature: ip-intelligence-analyzer, Property 23: Batch Mode Output Format Restriction
Validates: Requirements 11.2, 11.3
"""

import tempfile

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.ip_sentinel.batch import (
    BatchProcessor,
    InvalidOutputFormatError
)
from src.ip_sentinel.analyzer import IPAnalyzer
from src.ip_sentinel.config import Config


class TestBatchModeOutputFormatRestriction:
    """Property tests for batch mode output format restriction."""

    @given(st.sampled_from(['json', 'html']))
    @settings(max_examples=100, deadline=None)
    def test_batch_mode_accepts_json_and_html_formats(self, format_type):
        """
        Property 23: Batch Mode Output Format Restriction
        For any batch mode execution with JSON or HTML format, the application should proceed.
        **Validates: Requirements 11.2, 11.3**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format=format_type,
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer
            analyzer = IPAnalyzer(config)

            # Should not raise InvalidOutputFormatError
            try:
                batch_processor = BatchProcessor(
                    analyzer=analyzer,
                    output_folder=temp_dir,
                    format_type=format_type,
                    parallel=False
                )

                # Verify processor was created successfully
                assert batch_processor is not None
                assert batch_processor.format_type == format_type
                assert batch_processor.file_manager.format_type == format_type

            except InvalidOutputFormatError:
                pytest.fail(
                    f"BatchProcessor should accept {format_type} format "
                    f"but raised InvalidOutputFormatError")

    @given(st.sampled_from(['human', 'text', 'xml', 'csv', 'yaml']))
    @settings(max_examples=100, deadline=None)
    def test_batch_mode_rejects_non_json_html_formats(self, invalid_format):
        """
        Property 23: Batch Mode Output Format Restriction
        For any batch mode execution without JSON or HTML format, the application should reject it.
        **Validates: Requirements 11.2, 11.3**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format=invalid_format,
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer
            analyzer = IPAnalyzer(config)

            # Should raise InvalidOutputFormatError
            with pytest.raises(InvalidOutputFormatError) as exc_info:
                BatchProcessor(
                    analyzer=analyzer,
                    output_folder=temp_dir,
                    format_type=invalid_format,
                    parallel=False
                )

            # Error message should be clear
            error_msg = str(exc_info.value)
            assert 'json' in error_msg.lower() or 'html' in error_msg.lower()
            assert invalid_format in error_msg.lower()

    @given(
        st.sampled_from(['json', 'html']),
        st.booleans()
    )
    @settings(max_examples=100, deadline=None)
    def test_format_restriction_applies_to_both_sequential_and_parallel(
            self, format_type, parallel):
        """
        Property 23: Batch Mode Output Format Restriction
        For any batch mode execution, format restriction should apply regardless of parallel flag.
        **Validates: Requirements 11.2, 11.3**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create minimal config
            config = Config(
                database_path=None,
                output_format=format_type,
                reporting_mode='dense',
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer
            analyzer = IPAnalyzer(config)

            # Should accept valid formats regardless of parallel flag
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type=format_type,
                parallel=parallel
            )

            assert batch_processor.format_type == format_type
            assert batch_processor.parallel == parallel

    @given(st.sampled_from(['json', 'html']))
    @settings(max_examples=100, deadline=None)
    def test_file_manager_enforces_format_restriction(self, format_type):
        """
        Property 23: Batch Mode Output Format Restriction
        For any FileOutputManager, format restriction should be enforced at initialization.
        **Validates: Requirements 11.2, 11.3**
        """
        from src.ip_sentinel.batch import FileOutputManager

        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Should accept valid formats
            file_manager = FileOutputManager(temp_dir, format_type)

            assert file_manager.format_type == format_type
            assert file_manager.extension == f".{format_type}"

    @given(st.sampled_from(['human', 'text', 'xml']))
    @settings(max_examples=100, deadline=None)
    def test_file_manager_rejects_invalid_formats(self, invalid_format):
        """
        Property 23: Batch Mode Output Format Restriction
        For any FileOutputManager with invalid format, initialization should fail.
        **Validates: Requirements 11.2, 11.3**
        """
        from src.ip_sentinel.batch import FileOutputManager

        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Should reject invalid formats
            with pytest.raises(InvalidOutputFormatError) as exc_info:
                FileOutputManager(temp_dir, invalid_format)

            # Error message should mention required formats
            error_msg = str(exc_info.value)
            assert 'json' in error_msg.lower() or 'html' in error_msg.lower()

    @given(
        st.sampled_from(['json', 'html']),
        st.sampled_from(['dense', 'full', 'full-err'])
    )
    @settings(max_examples=100, deadline=None)
    def test_format_restriction_independent_of_reporting_mode(
            self, format_type, reporting_mode):
        """
        Property 23: Batch Mode Output Format Restriction
        For any batch mode execution, format restriction should be independent of reporting mode.
        **Validates: Requirements 11.2, 11.3**
        """
        # Create temporary output folder
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create config with different reporting modes
            config = Config(
                database_path=None,
                output_format=format_type,
                reporting_mode=reporting_mode,
                force_internet=False,
                enabled_modules={},
                run_root=False,
                verify_ssl=True,
                verbose=False
            )

            # Create analyzer
            analyzer = IPAnalyzer(config)

            # Should accept valid formats regardless of reporting mode
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=temp_dir,
                format_type=format_type,
                parallel=False
            )

            assert batch_processor.format_type == format_type
            assert batch_processor.analyzer.config.reporting_mode == reporting_mode
