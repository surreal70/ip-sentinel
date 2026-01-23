"""
Property-based tests for filename sanitization.

Feature: ip-intelligence-analyzer, Property 27: Filename Sanitization
Validates: Requirements 11.16
"""

import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from src.ip_sentinel.batch import FileOutputManager


class TestFilenameSanitization:
    """Property tests for filename sanitization."""

    @given(st.ip_addresses(v=4))
    @settings(max_examples=100, deadline=None)
    def test_ipv4_filename_sanitization(self, ip):
        """
        Property 27: Filename Sanitization
        For any IPv4 address, filename should replace dots with underscores.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Should not contain dots (except in extension)
            name_without_ext = filename.rsplit('.', 1)[0]
            assert '.' not in name_without_ext

            # Should contain underscores instead
            assert '_' in name_without_ext

            # Should end with .json
            assert filename.endswith('.json')

            # Should be based on IP address
            ip_str = str(ip)
            expected = ip_str.replace('.', '_') + '.json'
            assert filename == expected

    @given(st.ip_addresses(v=6))
    @settings(max_examples=100, deadline=None)
    def test_ipv6_filename_sanitization(self, ip):
        """
        Property 27: Filename Sanitization
        For any IPv6 address, filename should replace colons with underscores.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Should not contain colons
            assert ':' not in filename

            # Should contain underscores
            assert '_' in filename

            # Should end with .json
            assert filename.endswith('.json')

            # Should be based on IP address
            ip_str = str(ip)
            expected = ip_str.replace(':', '_') + '.json'
            assert filename == expected

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_sanitized_filenames_are_filesystem_safe(self, ip):
        """
        Property 27: Filename Sanitization
        For any IP address, sanitized filename should be safe for all filesystems.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Should not contain filesystem-unsafe characters
            unsafe_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
            for char in unsafe_chars:
                # Allow colon only in extension separator
                if char == ':':
                    # No colons should be in the filename part
                    name_part = filename.rsplit('.', 1)[0]
                    assert char not in name_part
                else:
                    assert char not in filename

            # Should be a valid filename (can create file with it)
            test_path = Path(temp_dir) / filename
            try:
                test_path.touch()
                assert test_path.exists()
            except (OSError, ValueError) as e:
                pytest.fail(f"Sanitized filename '{filename}' is not filesystem-safe: {e}")

    @given(st.ip_addresses(), st.sampled_from(['json', 'html']))
    @settings(max_examples=100, deadline=None)
    def test_filename_extension_matches_format(self, ip, format_type):
        """
        Property 27: Filename Sanitization
        For any IP and format, filename extension should match the format type.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, format_type)

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Should end with correct extension
            assert filename.endswith(f'.{format_type}')

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_sanitized_filenames_are_unique_per_ip(self, ip):
        """
        Property 27: Filename Sanitization
        For any IP address, the same IP should always generate the same filename.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename multiple times
            filename1 = file_manager.generate_filename(ip)
            filename2 = file_manager.generate_filename(ip)
            filename3 = file_manager.generate_filename(ip)

            # Should be identical
            assert filename1 == filename2 == filename3

    @given(st.lists(st.ip_addresses(), min_size=2, max_size=10, unique=True))
    @settings(max_examples=100, deadline=None)
    def test_different_ips_generate_different_filenames(self, ip_list):
        """
        Property 27: Filename Sanitization
        For any list of unique IPs, each should generate a unique filename.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filenames for all IPs
            filenames = [file_manager.generate_filename(ip) for ip in ip_list]

            # All filenames should be unique
            assert len(filenames) == len(set(filenames))

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_filename_contains_no_spaces(self, ip):
        """
        Property 27: Filename Sanitization
        For any IP address, sanitized filename should contain no spaces.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Should not contain spaces
            assert ' ' not in filename

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_filename_is_ascii_compatible(self, ip):
        """
        Property 27: Filename Sanitization
        For any IP address, sanitized filename should be ASCII-compatible.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Should be ASCII-encodable
            try:
                filename.encode('ascii')
            except UnicodeEncodeError:
                pytest.fail(f"Filename '{filename}' is not ASCII-compatible")

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_filename_length_is_reasonable(self, ip):
        """
        Property 27: Filename Sanitization
        For any IP address, sanitized filename should have reasonable length.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Should be reasonable length (most filesystems support 255 chars)
            assert len(filename) < 255

            # Should not be empty
            assert len(filename) > 0

    @given(st.ip_addresses())
    @settings(max_examples=100, deadline=None)
    def test_get_output_path_combines_folder_and_filename(self, ip):
        """
        Property 27: Filename Sanitization
        For any IP address, output path should combine folder and sanitized filename.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Get output path
            output_path = file_manager.get_output_path(ip)

            # Should be a Path object
            assert isinstance(output_path, Path)

            # Parent should be output folder
            assert output_path.parent == Path(temp_dir)

            # Filename should match generated filename
            expected_filename = file_manager.generate_filename(ip)
            assert output_path.name == expected_filename

    @given(st.ip_addresses(v=4))
    @settings(max_examples=100, deadline=None)
    def test_ipv4_filename_reversible(self, ip):
        """
        Property 27: Filename Sanitization
        For any IPv4 address, we should be able to derive the IP from the filename.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Extract IP from filename
            name_without_ext = filename.rsplit('.', 1)[0]
            reconstructed_ip = name_without_ext.replace('_', '.')

            # Should match original IP
            assert reconstructed_ip == str(ip)

    @given(st.ip_addresses(v=6))
    @settings(max_examples=100, deadline=None)
    def test_ipv6_filename_reversible(self, ip):
        """
        Property 27: Filename Sanitization
        For any IPv6 address, we should be able to derive the IP from the filename.
        **Validates: Requirements 11.16**
        """
        # Create temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create file manager
            file_manager = FileOutputManager(temp_dir, 'json')

            # Generate filename
            filename = file_manager.generate_filename(ip)

            # Extract IP from filename
            name_without_ext = filename.rsplit('.', 1)[0]
            reconstructed_ip = name_without_ext.replace('_', ':')

            # Should match original IP (accounting for IPv6 compression)
            import ipaddress
            assert ipaddress.ip_address(reconstructed_ip) == ip
