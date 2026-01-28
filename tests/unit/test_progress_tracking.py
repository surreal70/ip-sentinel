"""
Unit tests for progress tracking functionality.

Tests progress bar rendering, sub-progress stage transitions,
and progress accuracy with various batch sizes.

Validates: Requirements 11.11, 11.12
"""

import pytest
from io import StringIO
from unittest.mock import patch
from src.ip_sentinel.batch import ProgressTracker


class TestProgressTrackerInitialization:
    """Test progress tracker initialization."""

    def test_sequential_mode_initialization(self):
        """Test initialization in sequential mode."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        assert tracker.total_ips == 10
        assert tracker.parallel is False
        assert tracker.current_ip == 0
        assert tracker.current_ip_address is None
        assert tracker._lock is None

    def test_parallel_mode_initialization(self):
        """Test initialization in parallel mode."""
        tracker = ProgressTracker(total_ips=10, parallel=True)

        assert tracker.total_ips == 10
        assert tracker.parallel is True
        assert tracker._lock is not None


class TestOverallProgressUpdates:
    """Test overall progress indicator updates."""

    def test_update_overall_progress_basic(self):
        """Test basic overall progress update."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        tracker.update_overall_progress(5, "192.168.1.5")

        assert tracker.current_ip == 5
        assert tracker.current_ip_address == "192.168.1.5"

    def test_update_overall_progress_without_ip_address(self):
        """Test overall progress update without IP address."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        tracker.update_overall_progress(3)

        assert tracker.current_ip == 3
        assert tracker.current_ip_address is None

    def test_update_overall_progress_sequence(self):
        """Test sequential overall progress updates."""
        tracker = ProgressTracker(total_ips=5, parallel=False)

        for i in range(1, 6):
            tracker.update_overall_progress(i, f"192.168.1.{i}")
            assert tracker.current_ip == i
            assert tracker.current_ip_address == f"192.168.1.{i}"


class TestProgressDisplay:
    """Test progress display functionality."""

    @patch('sys.stdout.isatty', return_value=False)
    def test_display_progress_non_interactive(self, mock_isatty):
        """Test that progress is not displayed in non-interactive mode."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        # Should not raise any errors
        tracker.display_progress()
        tracker.update_overall_progress(5, "192.168.1.5")

    @patch('sys.stdout.isatty', return_value=True)
    @patch('sys.stdout', new_callable=StringIO)
    def test_display_progress_interactive(self, mock_stdout, mock_isatty):
        """Test progress display in interactive mode."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        tracker.update_overall_progress(5, "192.168.1.5")

        output = mock_stdout.getvalue()
        # Should contain progress information
        assert "5/10" in output or "192.168.1.5" in output

    def test_complete_clears_display(self):
        """Test that complete() method clears the display."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        tracker.update_overall_progress(5, "192.168.1.5")
        # Should not raise any errors
        tracker.complete()


class TestThreadSafety:
    """Test thread safety in parallel mode."""

    def test_parallel_mode_has_lock(self):
        """Test that parallel mode creates a lock."""
        tracker = ProgressTracker(total_ips=10, parallel=True)

        assert tracker._lock is not None

    def test_sequential_mode_no_lock(self):
        """Test that sequential mode doesn't create a lock."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        assert tracker._lock is None

    def test_parallel_updates_dont_raise_errors(self):
        """Test that parallel updates work without errors."""
        tracker = ProgressTracker(total_ips=10, parallel=True)

        # These should work with locking
        tracker.update_overall_progress(5, "192.168.1.5")


class TestProgressAccuracy:
    """Test progress accuracy with various batch sizes."""

    @pytest.mark.parametrize("total_ips", [1, 5, 10, 50, 100, 1024])
    def test_progress_accuracy_various_sizes(self, total_ips):
        """Test progress accuracy with different batch sizes."""
        tracker = ProgressTracker(total_ips=total_ips, parallel=False)

        # Process all IPs
        for i in range(1, total_ips + 1):
            tracker.update_overall_progress(i, f"192.168.1.{i}")

            # Verify accuracy
            assert tracker.current_ip == i
            assert tracker.total_ips == total_ips

            # Calculate expected percentage
            expected_percent = (i / total_ips * 100)
            actual_percent = (tracker.current_ip / tracker.total_ips * 100)

            assert abs(actual_percent - expected_percent) < 0.01

    def test_progress_at_boundaries(self):
        """Test progress at boundary conditions."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        # Start (0%)
        assert tracker.current_ip == 0

        # First IP (10%)
        tracker.update_overall_progress(1, "192.168.1.1")
        assert tracker.current_ip == 1

        # Last IP (100%)
        tracker.update_overall_progress(10, "192.168.1.10")
        assert tracker.current_ip == 10


class TestStructuralChanges:
    """Test structural changes after refactoring.
    
    Validates: Requirements 1.2, 1.4, 1.5
    """

    def test_stages_attribute_removed(self):
        """Test that STAGES class attribute has been removed."""
        assert not hasattr(ProgressTracker, 'STAGES'), \
            "STAGES class attribute should be removed"

    def test_current_stage_attribute_removed(self):
        """Test that current_stage instance attribute has been removed."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        assert not hasattr(tracker, 'current_stage'), \
            "current_stage instance attribute should be removed"

    def test_stage_progress_attribute_removed(self):
        """Test that stage_progress instance attribute has been removed."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        assert not hasattr(tracker, 'stage_progress'), \
            "stage_progress instance attribute should be removed"

    def test_start_stage_method_removed(self):
        """Test that start_stage() method has been removed."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        assert not hasattr(tracker, 'start_stage'), \
            "start_stage() method should be removed"

    def test_complete_stage_method_removed(self):
        """Test that complete_stage() method has been removed."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        assert not hasattr(tracker, 'complete_stage'), \
            "complete_stage() method should be removed"

    def test_update_sub_progress_method_removed(self):
        """Test that update_sub_progress() method has been removed."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        assert not hasattr(tracker, 'update_sub_progress'), \
            "update_sub_progress() method should be removed"

    def test_update_sub_progress_unsafe_method_removed(self):
        """Test that _update_sub_progress_unsafe() method has been removed."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        assert not hasattr(tracker, '_update_sub_progress_unsafe'), \
            "_update_sub_progress_unsafe() method should be removed"

    def test_progress_tracker_instantiation(self):
        """Test that ProgressTracker can be instantiated without errors."""
        # Sequential mode
        tracker_seq = ProgressTracker(total_ips=10, parallel=False)
        assert tracker_seq is not None
        assert tracker_seq.total_ips == 10
        assert tracker_seq.parallel is False

        # Parallel mode
        tracker_par = ProgressTracker(total_ips=20, parallel=True)
        assert tracker_par is not None
        assert tracker_par.total_ips == 20
        assert tracker_par.parallel is True

    def test_essential_attributes_preserved(self):
        """Test that essential attributes are preserved after refactoring."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        
        # These attributes should still exist
        assert hasattr(tracker, 'total_ips')
        assert hasattr(tracker, 'parallel')
        assert hasattr(tracker, 'current_ip')
        assert hasattr(tracker, 'current_ip_address')
        assert hasattr(tracker, '_lock')
        assert hasattr(tracker, '_displayed')

    def test_essential_methods_preserved(self):
        """Test that essential methods are preserved after refactoring."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        
        # These methods should still exist
        assert hasattr(tracker, 'update_overall_progress')
        assert hasattr(tracker, 'display_progress')
        assert hasattr(tracker, 'complete')
        assert hasattr(tracker, '_update_overall_progress_unsafe')


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_single_ip_batch(self):
        """Test progress tracking with single IP."""
        tracker = ProgressTracker(total_ips=1, parallel=False)

        tracker.update_overall_progress(1, "192.168.1.1")

        assert tracker.current_ip == 1
        assert tracker.total_ips == 1

    def test_maximum_batch_size(self):
        """Test progress tracking with maximum batch size."""
        tracker = ProgressTracker(total_ips=1024, parallel=False)

        # Test first and last
        tracker.update_overall_progress(1, "192.168.1.1")
        assert tracker.current_ip == 1

        tracker.update_overall_progress(1024, "192.168.4.0")
        assert tracker.current_ip == 1024

    def test_ipv6_addresses(self):
        """Test progress tracking with IPv6 addresses."""
        tracker = ProgressTracker(total_ips=5, parallel=False)

        ipv6_addresses = [
            "2001:db8::1",
            "2001:db8::2",
            "fe80::1",
            "::1",
            "2001:db8:85a3::8a2e:370:7334"
        ]

        for i, ip in enumerate(ipv6_addresses, 1):
            tracker.update_overall_progress(i, ip)
            assert tracker.current_ip_address == ip


class TestAPICompatibility:
    """Test API compatibility for backward compatibility.
    
    Validates: Requirements 8.1, 8.2, 8.3
    """

    def test_update_overall_progress_method_signature(self):
        """Test update_overall_progress() method exists with correct parameters.
        
        Validates: Requirement 8.1
        """
        tracker = ProgressTracker(total_ips=10, parallel=False)
        
        # Verify method exists
        assert hasattr(tracker, 'update_overall_progress'), \
            "update_overall_progress() method should exist"
        
        # Test method can be called with required parameters
        # Should accept: current (int), ip_address (Optional[str])
        tracker.update_overall_progress(5)  # Without ip_address
        assert tracker.current_ip == 5
        
        tracker.update_overall_progress(7, "192.168.1.7")  # With ip_address
        assert tracker.current_ip == 7
        assert tracker.current_ip_address == "192.168.1.7"
        
        # Verify method signature using inspect
        import inspect
        sig = inspect.signature(tracker.update_overall_progress)
        params = list(sig.parameters.keys())
        
        # Should have 'current' and 'ip_address' parameters
        assert 'current' in params, "Method should have 'current' parameter"
        assert 'ip_address' in params, "Method should have 'ip_address' parameter"
        
        # ip_address should have a default value (Optional)
        assert sig.parameters['ip_address'].default is not inspect.Parameter.empty or \
               sig.parameters['ip_address'].default is None, \
               "ip_address parameter should be optional"

    def test_complete_method_signature(self):
        """Test complete() method exists with correct parameters.
        
        Validates: Requirement 8.2
        """
        tracker = ProgressTracker(total_ips=10, parallel=False)
        
        # Verify method exists
        assert hasattr(tracker, 'complete'), \
            "complete() method should exist"
        
        # Test method can be called without parameters
        tracker.complete()  # Should not raise any errors
        
        # Verify method signature using inspect
        import inspect
        sig = inspect.signature(tracker.complete)
        params = list(sig.parameters.keys())
        
        # Should have no required parameters (only self)
        assert len(params) == 0, "complete() should not have required parameters"

    def test_init_method_signature(self):
        """Test __init__() method accepts total_ips and parallel parameters.
        
        Validates: Requirement 8.3
        """
        # Test with both parameters
        tracker1 = ProgressTracker(total_ips=10, parallel=False)
        assert tracker1.total_ips == 10
        assert tracker1.parallel is False
        
        tracker2 = ProgressTracker(total_ips=20, parallel=True)
        assert tracker2.total_ips == 20
        assert tracker2.parallel is True
        
        # Test with only required parameter (parallel should default to False)
        tracker3 = ProgressTracker(total_ips=15)
        assert tracker3.total_ips == 15
        assert tracker3.parallel is False
        
        # Verify method signature using inspect
        import inspect
        sig = inspect.signature(ProgressTracker.__init__)
        params = list(sig.parameters.keys())
        
        # Should have 'self', 'total_ips', and 'parallel' parameters
        assert 'total_ips' in params, "__init__ should have 'total_ips' parameter"
        assert 'parallel' in params, "__init__ should have 'parallel' parameter"
        
        # parallel should have a default value
        assert sig.parameters['parallel'].default is not inspect.Parameter.empty, \
               "parallel parameter should have a default value"

    def test_zero_ips_edge_case(self):
        """Test progress tracking with 0 IPs.
        
        Validates: Requirements 3.1, 3.2
        """
        tracker = ProgressTracker(total_ips=0, parallel=False)
        
        assert tracker.total_ips == 0
        assert tracker.current_ip == 0
        assert tracker.completed_scans == 0
        
        # Display should handle 0 IPs without errors
        tracker.display_progress()
        
        # Complete should work with 0 IPs
        tracker.complete()

    def test_single_ip_edge_case(self):
        """Test progress tracking with 1 IP.
        
        Validates: Requirements 3.1, 3.2
        """
        tracker = ProgressTracker(total_ips=1, parallel=False)
        
        assert tracker.total_ips == 1
        assert tracker.current_ip == 0
        assert tracker.completed_scans == 0
        
        # Update to first IP
        tracker.update_overall_progress(1, "192.168.1.1")
        assert tracker.current_ip == 1
        
        # Mark as completed
        tracker.mark_completed()
        assert tracker.completed_scans == 1
        
        # Complete should work
        tracker.complete()

    def test_maximum_batch_size_edge_case(self):
        """Test progress tracking with maximum batch size (1024 IPs).
        
        Validates: Requirements 3.1, 3.2
        """
        tracker = ProgressTracker(total_ips=1024, parallel=False)
        
        assert tracker.total_ips == 1024
        assert tracker.current_ip == 0
        assert tracker.completed_scans == 0
        
        # Update to first IP
        tracker.update_overall_progress(1, "192.168.1.1")
        assert tracker.current_ip == 1
        
        # Mark first as completed
        tracker.mark_completed()
        assert tracker.completed_scans == 1
        
        # Update to last IP
        tracker.update_overall_progress(1024, "192.168.4.0")
        assert tracker.current_ip == 1024
        
        # Mark last as completed
        tracker.mark_completed()
        assert tracker.completed_scans == 2
        
        # Complete should work
        tracker.complete()

    def test_completion_counter_at_zero_boundary(self):
        """Test completion counter at zero boundary.
        
        Validates: Requirements 3.1, 3.2
        """
        tracker = ProgressTracker(total_ips=10, parallel=False)
        
        # Initial state
        assert tracker.completed_scans == 0
        
        # Display should show 0/10
        tracker.display_progress()

    def test_completion_counter_at_total_boundary(self):
        """Test completion counter at total_ips boundary.
        
        Validates: Requirements 3.1, 3.2
        """
        tracker = ProgressTracker(total_ips=5, parallel=False)
        
        # Mark all as completed
        for i in range(5):
            tracker.mark_completed()
        
        # Should be at boundary
        assert tracker.completed_scans == 5
        assert tracker.completed_scans == tracker.total_ips
        
        # Attempting to mark more should not exceed total
        tracker.mark_completed()
        assert tracker.completed_scans == 5  # Should stay at 5, not exceed

    def test_completion_counter_bounds_checking(self):
        """Test that completion counter never exceeds total_ips.
        
        Validates: Requirements 3.1, 3.2
        """
        tracker = ProgressTracker(total_ips=3, parallel=False)
        
        # Mark completed multiple times beyond total
        for i in range(10):
            tracker.mark_completed()
        
        # Should be clamped to total_ips
        assert tracker.completed_scans == 3
        assert tracker.completed_scans <= tracker.total_ips
