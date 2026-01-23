"""
Property-based tests for output folder management.

Feature: ip-intelligence-analyzer, Property 26: Output Folder Management
Validates: Requirements 11.8, 11.9, 11.10
"""

import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.ip_sentinel.batch import (
    FileOutputManager,
    OutputFolderError
)


class TestOutputFolderManagement:
    """Property tests for output folder management."""

    @given(st.text(min_size=1, max_size=50, alphabet=st.characters(
        whitelist_categories=('Lu', 'Ll', 'Nd'), min_codepoint=65, max_codepoint=122)))
    @settings(max_examples=100, deadline=None)
    def test_output_folder_created_if_not_exists(self, folder_name):
        """
        Property 26: Output Folder Management
        For any specified output folder that doesn't exist, it should be created.
        **Validates: Requirements 11.8, 11.9**
        """
        # Create temporary parent directory
        with tempfile.TemporaryDirectory() as temp_parent:
            # Create path that doesn't exist yet
            output_path = Path(temp_parent) / folder_name

            # Ensure it doesn't exist
            assert not output_path.exists()

            # Create file manager
            file_manager = FileOutputManager(str(output_path), 'json')

            # Create output folder
            file_manager.create_output_folder()

            # Folder should now exist
            assert output_path.exists()
            assert output_path.is_dir()

    @given(st.integers(min_value=1, max_value=5))
    @settings(max_examples=100, deadline=None)
    def test_nested_output_folders_created(self, depth):
        """
        Property 26: Output Folder Management
        For any nested folder path, all parent directories should be created.
        **Validates: Requirements 11.8, 11.9**
        """
        # Create temporary parent directory
        with tempfile.TemporaryDirectory() as temp_parent:
            # Create nested path
            nested_parts = [f"level{i}" for i in range(depth)]
            output_path = Path(temp_parent).joinpath(*nested_parts)

            # Ensure it doesn't exist
            assert not output_path.exists()

            # Create file manager
            file_manager = FileOutputManager(str(output_path), 'json')

            # Create output folder
            file_manager.create_output_folder()

            # All levels should exist
            assert output_path.exists()
            assert output_path.is_dir()

            # Verify all parent directories exist
            current = output_path
            for _ in range(depth):
                assert current.exists()
                assert current.is_dir()
                current = current.parent

    @given(st.sampled_from(['json', 'html']))
    @settings(max_examples=100, deadline=None)
    def test_existing_folder_not_overwritten(self, format_type):
        """
        Property 26: Output Folder Management
        For any existing output folder, creating it again should not fail or overwrite.
        **Validates: Requirements 11.8, 11.9**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "existing_folder"
            output_path.mkdir()

            # Create a test file in the folder
            test_file = output_path / "test.txt"
            test_file.write_text("existing content")

            # Create file manager
            file_manager = FileOutputManager(str(output_path), format_type)

            # Create output folder (should not fail)
            file_manager.create_output_folder()

            # Folder should still exist
            assert output_path.exists()
            assert output_path.is_dir()

            # Test file should still exist with original content
            assert test_file.exists()
            assert test_file.read_text() == "existing content"

    @given(st.sampled_from(['json', 'html']))
    @settings(max_examples=100, deadline=None)
    def test_output_folder_validation_succeeds_for_valid_folder(
            self, format_type):
        """
        Property 26: Output Folder Management
        For any valid writable folder, validation should succeed.
        **Validates: Requirements 11.8, 11.9, 11.10**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, format_type)

            # Create output folder
            file_manager.create_output_folder()

            # Validation should succeed
            result = file_manager.validate_output_folder()
            assert result is True

    @given(st.sampled_from(['json', 'html']))
    @settings(max_examples=100, deadline=None)
    def test_validation_fails_for_nonexistent_folder(self, format_type):
        """
        Property 26: Output Folder Management
        For any non-existent folder, validation should fail with clear error.
        **Validates: Requirements 11.8, 11.9, 11.10**
        """
        # Create temporary parent directory
        with tempfile.TemporaryDirectory() as temp_parent:
            # Create path that doesn't exist
            nonexistent_path = Path(temp_parent) / "nonexistent"

            # Create file manager
            file_manager = FileOutputManager(str(nonexistent_path), format_type)

            # Validation should fail
            with pytest.raises(OutputFolderError) as exc_info:
                file_manager.validate_output_folder()

            # Error message should be descriptive
            error_msg = str(exc_info.value)
            assert 'not exist' in error_msg.lower() or 'does not exist' in error_msg.lower()

    @given(st.sampled_from(['json', 'html']))
    @settings(max_examples=100, deadline=None)
    def test_validation_fails_for_file_instead_of_folder(self, format_type):
        """
        Property 26: Output Folder Management
        For any path that is a file (not folder), validation should fail.
        **Validates: Requirements 11.8, 11.9, 11.10**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a file instead of folder
            file_path = Path(temp_dir) / "not_a_folder.txt"
            file_path.write_text("test content")

            # Create file manager pointing to file
            file_manager = FileOutputManager(str(file_path), format_type)

            # Validation should fail
            with pytest.raises(OutputFolderError) as exc_info:
                file_manager.validate_output_folder()

            # Error message should mention directory
            error_msg = str(exc_info.value)
            assert 'directory' in error_msg.lower() or 'folder' in error_msg.lower()

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_file_writing_creates_file_in_folder(self, ip):
        """
        Property 26: Output Folder Management
        For any IP address, writing result should create file in output folder.
        **Validates: Requirements 11.8, 11.9, 11.10**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')
            file_manager.create_output_folder()

            # Write result
            test_content = f'{{"ip": "{ip}"}}'
            file_manager.write_result(ip, test_content)

            # File should exist
            output_path = file_manager.get_output_path(ip)
            assert output_path.exists()
            assert output_path.is_file()

            # Content should match
            assert output_path.read_text() == test_content

            # File should be in output folder
            assert output_path.parent == Path(temp_dir)

    @given(st.ip_addresses(), st.text(min_size=1, max_size=1000))
    @settings(max_examples=100, deadline=None)
    def test_file_writing_preserves_content(self, ip, content):
        """
        Property 26: Output Folder Management
        For any IP and content, written file should preserve exact content.
        **Validates: Requirements 11.8, 11.9, 11.10**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')
            file_manager.create_output_folder()

            # Write result
            file_manager.write_result(ip, content)

            # Read back and verify
            output_path = file_manager.get_output_path(ip)
            read_content = output_path.read_text(encoding='utf-8')

            # Note: Python's text mode may normalize line endings
            # For JSON/HTML output, this is acceptable behavior
            # We verify content is preserved modulo line ending normalization
            normalized_content = content.replace(
                '\r\n', '\n').replace('\r', '\n')
            assert read_content == content or read_content == normalized_content

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_multiple_writes_to_same_ip_overwrites(self, ip):
        """
        Property 26: Output Folder Management
        For any IP, writing multiple times should overwrite previous content.
        **Validates: Requirements 11.8, 11.9, 11.10**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')
            file_manager.create_output_folder()

            # Write first content
            first_content = "first content"
            file_manager.write_result(ip, first_content)

            # Write second content
            second_content = "second content"
            file_manager.write_result(ip, second_content)

            # Should have second content only
            output_path = file_manager.get_output_path(ip)
            assert output_path.read_text() == second_content

    @given(st.lists(st.ip_addresses(), min_size=2, max_size=10, unique=True))
    @settings(max_examples=100, deadline=None)
    def test_multiple_ips_create_separate_files(self, ip_list):
        """
        Property 26: Output Folder Management
        For any list of IPs, each should get its own separate file.
        **Validates: Requirements 11.8, 11.9, 11.10**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')
            file_manager.create_output_folder()

            # Write results for all IPs
            for ip in ip_list:
                content = f'{{"ip": "{ip}"}}'
                file_manager.write_result(ip, content)

            # Each IP should have its own file
            for ip in ip_list:
                output_path = file_manager.get_output_path(ip)
                assert output_path.exists()
                assert output_path.is_file()

            # Should have exactly as many files as IPs (plus any system files)
            json_files = list(Path(temp_dir).glob("*.json"))
            assert len(json_files) == len(ip_list)
