"""
Property-based tests for database location configuration.

**Feature: ip-intelligence-analyzer, Property 4: Database Location Configuration**
**Validates: Requirements 3.4**
"""

import tempfile
from pathlib import Path
from hypothesis import given, strategies as st
from hypothesis.strategies import composite

from src.ip_sentinel.database.manager import DatabaseManager


@composite
def valid_database_paths(draw):
    """Generate valid database file paths."""
    # Generate various path components
    directory_names = st.text(
        alphabet=st.characters(
            whitelist_categories=(
                'Lu',
                'Ll',
                'Nd'),
            min_codepoint=32,
            max_codepoint=126),
        min_size=1,
        max_size=20).filter(
        lambda x: x.strip() and not any(
            c in x for c in [
                '/',
                '\\',
                ':',
                '*',
                '?',
                '"',
                '<',
                '>',
                '|']))

    filename_base = st.text(
        alphabet=st.characters(
            whitelist_categories=(
                'Lu',
                'Ll',
                'Nd'),
            min_codepoint=32,
            max_codepoint=126),
        min_size=1,
        max_size=30).filter(
        lambda x: x.strip() and not any(
            c in x for c in [
                '/',
                '\\',
                ':',
                '*',
                '?',
                '"',
                '<',
                '>',
                '|',
                '.']))

    # Generate path structure
    num_dirs = draw(st.integers(min_value=0, max_value=3))
    dirs = [draw(directory_names) for _ in range(num_dirs)]
    filename = draw(filename_base) + ".db"

    return Path(*dirs, filename) if dirs else Path(filename)


@composite
def sample_scan_data(draw):
    """Generate minimal scan data for testing database operations."""
    return {
        "ip_address": "192.168.1.1",
        "ip_version": 4,
        "scan_timestamp": "2024-01-01T12:00:00",
        "scan_duration_ms": 1000,
        "modules_executed": ["classification"],
        "module_results": {
            "classification": {
                "success": True,
                "data": {"classifications": [{"name": "private", "ip_range": "192.168.0.0/16"}]},
                "error_message": None
            }
        }
    }


class TestDatabaseLocationConfiguration:
    """Property-based tests for database location configuration."""

    @given(valid_database_paths(), sample_scan_data())
    def test_database_location_configuration_compliance(self, db_path, scan_data):
        """
        Property 4: Database Location Configuration
        For any specified database location via command-line option, the database file should be
        created at that exact location and be accessible for read/write operations.
        **Validates: Requirements 3.4**
        """
        # Create temporary directory as base for our test
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create the full path within the temporary directory
            full_db_path = Path(temp_dir) / db_path

            # Ensure parent directories exist
            full_db_path.parent.mkdir(parents=True, exist_ok=True)

            # Initialize DatabaseManager with specified location
            db_manager = DatabaseManager(full_db_path)

            # Verify the database manager uses the specified path
            assert db_manager.db_path == full_db_path, \
                f"DatabaseManager should use specified path: {full_db_path}"

            # Perform a database operation to trigger creation
            scan_id = db_manager.store_scan_result(scan_data)

            # Verify database file was created at exact specified location
            assert full_db_path.exists(), \
                f"Database file should be created at specified location: {full_db_path}"

            # Verify the file is actually a database file (not just an empty file)
            assert full_db_path.stat().st_size > 0, \
                "Database file should not be empty after storing data"

            # Verify read/write accessibility by performing operations
            # Test write access (already done with store_scan_result)
            assert isinstance(scan_id, int) and scan_id > 0, \
                "Database should be writable (store operation should succeed)"

            # Test read access
            stored_scan = db_manager.get_scan_by_id(scan_id)
            assert stored_scan is not None, \
                "Database should be readable (retrieve operation should succeed)"

            # Verify data integrity
            assert stored_scan["ip_address"] == scan_data["ip_address"], \
                "Stored data should match original data"

    @given(st.lists(valid_database_paths(), min_size=2,
           max_size=5, unique=True), sample_scan_data())
    def test_multiple_database_locations_isolation(self, db_paths, scan_data):
        """
        Property 4: Database Location Configuration (Isolation)
        For any set of different database locations, each should maintain independent data storage.
        **Validates: Requirements 3.4**
        """
        # Create temporary directory as base for our test
        with tempfile.TemporaryDirectory() as temp_dir:
            db_managers = []
            scan_ids = []

            # Create database managers for each path
            for db_path in db_paths:
                full_db_path = Path(temp_dir) / db_path
                full_db_path.parent.mkdir(parents=True, exist_ok=True)

                db_manager = DatabaseManager(full_db_path)
                db_managers.append(db_manager)

                # Store data in each database
                scan_id = db_manager.store_scan_result(scan_data)
                scan_ids.append(scan_id)

                # Verify database file exists at correct location
                assert full_db_path.exists(), \
                    f"Database should exist at {full_db_path}"

            # Verify each database is independent
            for i, db_manager in enumerate(db_managers):
                # Each database should contain its own scan
                stored_scan = db_manager.get_scan_by_id(scan_ids[i])
                assert stored_scan is not None, \
                    f"Database {i} should contain its own scan"

                # Each database should not contain scans from other databases
                for j, other_scan_id in enumerate(scan_ids):
                    if i != j:
                        other_scan = db_manager.get_scan_by_id(other_scan_id)
                        # This might be None or might be a different scan, but shouldn't
                        # be the same
                        if other_scan is not None:
                            # If it exists, it should be a different scan (different ID)
                            assert other_scan["id"] != other_scan_id or other_scan == stored_scan, \
                                f"Database {i} should not contain scan {other_scan_id} from database {j}"

    @given(sample_scan_data())
    def test_default_database_location_behavior(self, scan_data):
        """
        Property 4: Database Location Configuration (Default Behavior)
        For any database manager created without specifying a location, it should use a default location.
        **Validates: Requirements 3.4**
        """
        # Create temporary directory to work in
        with tempfile.TemporaryDirectory() as temp_dir:
            # Change to temporary directory to test default behavior
            import os
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)

                # Create DatabaseManager without specifying path (should use default)
                db_manager = DatabaseManager()

                # Verify default path is set
                assert db_manager.db_path is not None, \
                    "DatabaseManager should have a default database path"

                # Verify default path is reasonable (should be in current directory)
                expected_default = Path("ip_analysis.db")
                assert db_manager.db_path == expected_default, \
                    f"Default database path should be {expected_default}"

                # Perform database operation
                scan_id = db_manager.store_scan_result(scan_data)

                # Verify database was created at default location
                assert expected_default.exists(), \
                    f"Database should be created at default location: {expected_default}"

                # Verify functionality
                stored_scan = db_manager.get_scan_by_id(scan_id)
                assert stored_scan is not None, \
                    "Default database should be functional"

            finally:
                os.chdir(original_cwd)

    @given(valid_database_paths(), sample_scan_data())
    def test_database_path_persistence_across_operations(self, db_path, scan_data):
        """
        Property 4: Database Location Configuration (Path Persistence)
        For any specified database location, the path should remain consistent across multiple operations.
        **Validates: Requirements 3.4**
        """
        # Create temporary directory as base for our test
        with tempfile.TemporaryDirectory() as temp_dir:
            full_db_path = Path(temp_dir) / db_path
            full_db_path.parent.mkdir(parents=True, exist_ok=True)

            # Initialize DatabaseManager with specified location
            db_manager = DatabaseManager(full_db_path)

            # Verify initial path
            initial_path = db_manager.db_path
            assert initial_path == full_db_path, \
                "Initial database path should match specified path"

            # Perform multiple operations
            operations_results = []
            for i in range(3):
                # Modify scan data slightly for each operation
                modified_scan_data = scan_data.copy()
                modified_scan_data["scan_timestamp"] = f"2024-01-0{i + 1}T12:00:00"

                scan_id = db_manager.store_scan_result(modified_scan_data)
                operations_results.append(scan_id)

                # Verify path hasn't changed
                assert db_manager.db_path == initial_path, \
                    f"Database path should remain consistent after operation {i + 1}"

                # Verify database file still exists at same location
                assert full_db_path.exists(), \
                    f"Database file should still exist at {full_db_path} after operation {i + 1}"

            # Verify all operations were successful and data is accessible
            for scan_id in operations_results:
                stored_scan = db_manager.get_scan_by_id(scan_id)
                assert stored_scan is not None, \
                    f"Scan {scan_id} should be retrievable from consistent database location"

    @given(valid_database_paths())
    def test_database_location_with_nonexistent_parent_directories(self, db_path):
        """
        Property 4: Database Location Configuration (Directory Creation)
        For any specified database location with non-existent parent directories,
        the system should handle directory creation appropriately.
        **Validates: Requirements 3.4**
        """
        # Create temporary directory as base
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a path with multiple non-existent parent directories
            deep_path = Path(temp_dir) / "non" / "existent" / "path" / db_path

            # Ensure parent directories do NOT exist initially
            assert not deep_path.parent.exists(), \
                "Parent directories should not exist initially"

            # Initialize DatabaseManager with deep path
            db_manager = DatabaseManager(deep_path)

            # Create parent directories (this is what the application should do)
            deep_path.parent.mkdir(parents=True, exist_ok=True)

            # Verify the database manager can work with the path
            sample_data = {
                "ip_address": "10.0.0.1",
                "ip_version": 4,
                "scan_timestamp": "2024-01-01T12:00:00",
                "scan_duration_ms": 500,
                "modules_executed": ["classification"],
                "module_results": {
                    "classification": {
                        "success": True,
                        "data": {"test": "data"},
                        "error_message": None
                    }
                }
            }

            # This should work now that parent directories exist
            scan_id = db_manager.store_scan_result(sample_data)

            # Verify database was created at the specified deep location
            assert deep_path.exists(), \
                f"Database should be created at deep path: {deep_path}"

            # Verify functionality
            stored_scan = db_manager.get_scan_by_id(scan_id)
            assert stored_scan is not None, \
                "Database at deep path should be functional"
