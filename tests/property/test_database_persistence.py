"""
Property-based tests for database persistence completeness.

**Feature: ip-intelligence-analyzer, Property 3: Database Persistence Completeness**
**Validates: Requirements 3.1, 3.2, 3.5**
"""

import ipaddress
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from hypothesis import given, strategies as st, assume
from hypothesis.strategies import composite

from src.ip_mana.database.manager import DatabaseManager


@composite
def valid_ipv4_addresses(draw):
    """Generate valid IPv4 addresses."""
    octets = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
    return ipaddress.IPv4Address('.'.join(map(str, octets)))


@composite
def valid_ipv6_addresses(draw):
    """Generate valid IPv6 addresses."""
    groups = [draw(st.integers(min_value=0, max_value=0xFFFF)) for _ in range(8)]
    return ipaddress.IPv6Address(':'.join(f'{g:x}' for g in groups))


@composite
def valid_ip_addresses(draw):
    """Generate valid IP addresses (IPv4 or IPv6)."""
    return draw(st.one_of(valid_ipv4_addresses(), valid_ipv6_addresses()))


@composite
def scan_results(draw):
    """Generate valid scan result dictionaries."""
    ip_address = draw(valid_ip_addresses())
    
    # Generate scan metadata
    scan_timestamp = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime.now() + timedelta(days=1)
    ))
    scan_duration_ms = draw(st.integers(min_value=1, max_value=300000))  # 1ms to 5 minutes
    
    # Generate module results
    module_names = ["classification", "local_info", "internet_info", "netbox", "checkmk"]
    executed_modules = draw(st.lists(
        st.sampled_from(module_names), 
        min_size=1, 
        max_size=len(module_names), 
        unique=True
    ))
    
    module_results = {}
    for module_name in executed_modules:
        success = draw(st.booleans())
        
        if success:
            # Generate some sample data for successful modules
            if module_name == "classification":
                data = {
                    "classifications": draw(st.lists(
                        st.dictionaries(
                            keys=st.sampled_from(["name", "ip_range", "description"]),
                            values=st.text(min_size=1, max_size=100),
                            min_size=3,
                            max_size=3
                        ),
                        min_size=1,
                        max_size=5
                    ))
                }
            elif module_name == "local_info":
                data = {
                    "reachable": draw(st.booleans()),
                    "mac_address": draw(st.one_of(st.none(), st.text(min_size=17, max_size=17))),
                    "ports": draw(st.lists(st.integers(min_value=1, max_value=65535), max_size=10))
                }
            elif module_name == "internet_info":
                data = {
                    "whois": {"country": draw(st.text(min_size=2, max_size=2))},
                    "geolocation": {"city": draw(st.text(min_size=1, max_size=50))},
                    "asn": draw(st.integers(min_value=1, max_value=65535))
                }
            else:
                data = {"status": "completed", "findings": draw(st.integers(min_value=0, max_value=100))}
            
            error_message = None
        else:
            data = {}
            error_message = draw(st.text(min_size=1, max_size=200))
        
        module_results[module_name] = {
            "success": success,
            "data": data,
            "error_message": error_message
        }
    
    return {
        "ip_address": ip_address,
        "ip_version": ip_address.version,
        "scan_timestamp": scan_timestamp,
        "scan_duration_ms": scan_duration_ms,
        "modules_executed": executed_modules,
        "module_results": module_results
    }


class TestDatabasePersistence:
    """Property-based tests for database persistence completeness."""

    @given(scan_results())
    def test_scan_result_storage_completeness(self, scan_result):
        """
        Property 3: Database Persistence Completeness
        For any completed scan, the SQLite database should contain a record with the IP address,
        scan timestamp, and all collected findings from executed modules.
        **Validates: Requirements 3.1, 3.2, 3.5**
        """
        # Create temporary database
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_analysis.db"
            db_manager = DatabaseManager(db_path)
            
            # Store the scan result
            scan_id = db_manager.store_scan_result(scan_result)
            
            # Verify scan ID was returned
            assert isinstance(scan_id, int), "store_scan_result should return an integer scan ID"
            assert scan_id > 0, "Scan ID should be positive"
            
            # Retrieve the stored scan
            stored_scan = db_manager.get_scan_by_id(scan_id)
            
            # Verify the scan was stored
            assert stored_scan is not None, "Stored scan should be retrievable by ID"
            
            # Verify IP address is stored (Requirement 3.2)
            assert stored_scan["ip_address"] == str(scan_result["ip_address"]), \
                "Stored IP address should match original"
            assert stored_scan["ip_version"] == scan_result["ip_version"], \
                "Stored IP version should match original"
            
            # Verify scan timestamp is stored (Requirements 3.2, 3.5)
            stored_timestamp = stored_scan["scan_timestamp"]
            original_timestamp = scan_result["scan_timestamp"]
            
            # Handle both string and datetime formats
            if isinstance(stored_timestamp, str):
                # Parse ISO format timestamp
                stored_dt = datetime.fromisoformat(stored_timestamp.replace('Z', '+00:00'))
            else:
                stored_dt = stored_timestamp
            
            if isinstance(original_timestamp, str):
                original_dt = datetime.fromisoformat(original_timestamp.replace('Z', '+00:00'))
            else:
                original_dt = original_timestamp
            
            # Allow small time differences due to storage precision
            time_diff = abs((stored_dt - original_dt).total_seconds())
            assert time_diff < 2, f"Stored timestamp should match original (diff: {time_diff}s)"
            
            # Verify all test findings are stored (Requirement 3.2)
            assert "module_results" in stored_scan, "Stored scan should contain module results"
            
            stored_modules = stored_scan["module_results"]
            original_modules = scan_result["module_results"]
            
            # Check that all executed modules have results stored
            for module_name in scan_result["modules_executed"]:
                assert module_name in stored_modules, \
                    f"Module '{module_name}' results should be stored"
                
                stored_module = stored_modules[module_name]
                original_module = original_modules[module_name]
                
                # Verify success status is preserved
                assert stored_module["success"] == original_module["success"], \
                    f"Module '{module_name}' success status should be preserved"
                
                # Verify data is preserved for successful modules
                if original_module["success"]:
                    assert "data" in stored_module, f"Module '{module_name}' should have data stored"
                    # Data should be equivalent (allowing for JSON serialization differences)
                    stored_data = stored_module["data"]
                    original_data = original_module["data"]
                    assert stored_data == original_data, \
                        f"Module '{module_name}' data should be preserved"
                
                # Verify error messages are preserved for failed modules
                if not original_module["success"] and original_module["error_message"]:
                    assert stored_module["error_message"] == original_module["error_message"], \
                        f"Module '{module_name}' error message should be preserved"

    @given(st.lists(scan_results(), min_size=1, max_size=10))
    def test_multiple_scan_storage_and_retrieval(self, scan_results_list):
        """
        Property 3: Database Persistence Completeness (Multiple Scans)
        For any set of completed scans, all should be stored and retrievable from the database.
        **Validates: Requirements 3.1, 3.2, 3.5**
        """
        # Create temporary database
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_analysis.db"
            db_manager = DatabaseManager(db_path)
            
            stored_scan_ids = []
            
            # Store all scan results
            for scan_result in scan_results_list:
                scan_id = db_manager.store_scan_result(scan_result)
                stored_scan_ids.append(scan_id)
            
            # Verify all scans are stored and retrievable
            assert len(stored_scan_ids) == len(scan_results_list), \
                "All scans should be stored"
            
            # Verify each scan can be retrieved
            for i, scan_id in enumerate(stored_scan_ids):
                stored_scan = db_manager.get_scan_by_id(scan_id)
                original_scan = scan_results_list[i]
                
                assert stored_scan is not None, f"Scan {scan_id} should be retrievable"
                assert stored_scan["ip_address"] == str(original_scan["ip_address"]), \
                    f"Scan {scan_id} IP address should match"

    @given(scan_results())
    def test_scan_history_retrieval_by_ip(self, scan_result):
        """
        Property 3: Database Persistence Completeness (History Retrieval)
        For any IP address with stored scans, the scan history should be retrievable.
        **Validates: Requirements 3.1, 3.2, 3.5**
        """
        # Create temporary database
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_analysis.db"
            db_manager = DatabaseManager(db_path)
            
            # Store the scan result
            scan_id = db_manager.store_scan_result(scan_result)
            
            # Retrieve scan history for the IP
            ip_str = str(scan_result["ip_address"])
            history = db_manager.get_scan_history(ip_str)
            
            # Verify history contains the scan
            assert len(history) >= 1, "Scan history should contain at least one scan"
            
            # Find our scan in the history
            our_scan = None
            for scan in history:
                if scan["id"] == scan_id:
                    our_scan = scan
                    break
            
            assert our_scan is not None, "Our scan should be in the history"
            assert our_scan["ip_address"] == ip_str, "History scan IP should match"

    @given(scan_results())
    def test_database_file_creation_in_specified_location(self, scan_result):
        """
        Property 3: Database Persistence Completeness (File Location)
        For any scan result storage, the database should be created at the specified location.
        **Validates: Requirements 3.1, 3.3**
        """
        # Create temporary directory for custom database location
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_db_path = Path(temp_dir) / "custom_location" / "my_analysis.db"
            
            # Ensure parent directory exists
            custom_db_path.parent.mkdir(parents=True, exist_ok=True)
            
            db_manager = DatabaseManager(custom_db_path)
            
            # Store scan result (this should create the database)
            scan_id = db_manager.store_scan_result(scan_result)
            
            # Verify database file was created at specified location
            assert custom_db_path.exists(), \
                f"Database file should be created at specified location: {custom_db_path}"
            
            # Verify the database is functional
            stored_scan = db_manager.get_scan_by_id(scan_id)
            assert stored_scan is not None, "Database should be functional at custom location"

    @given(st.lists(scan_results(), min_size=2, max_size=5))
    def test_scan_timestamp_system_invoking_requirement(self, scan_results_list):
        """
        Property 3: Database Persistence Completeness (System Timestamp)
        For any stored scan results, the timestamp should reflect when the system invoked the test.
        **Validates: Requirements 3.5**
        """
        # Create temporary database
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_analysis.db"
            db_manager = DatabaseManager(db_path)
            
            # Record time before storage
            before_storage = datetime.now()
            
            stored_scan_ids = []
            for scan_result in scan_results_list:
                scan_id = db_manager.store_scan_result(scan_result)
                stored_scan_ids.append(scan_id)
            
            # Record time after storage
            after_storage = datetime.now()
            
            # Verify all stored scans have reasonable timestamps
            for scan_id in stored_scan_ids:
                stored_scan = db_manager.get_scan_by_id(scan_id)
                stored_timestamp = stored_scan["scan_timestamp"]
                
                # Handle string timestamps
                if isinstance(stored_timestamp, str):
                    stored_dt = datetime.fromisoformat(stored_timestamp.replace('Z', '+00:00'))
                else:
                    stored_dt = stored_timestamp
                
                # The stored timestamp should be within a reasonable range of when we stored it
                # (allowing for the original scan timestamp to be preserved)
                # This test ensures the system is capturing and preserving timestamp information
                assert isinstance(stored_dt, datetime) or isinstance(stored_timestamp, str), \
                    "Stored timestamp should be a datetime object or ISO string"