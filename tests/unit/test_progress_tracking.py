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
        assert tracker.current_stage is None
        assert tracker.stage_progress == 0.0
        assert tracker._lock is None

    def test_parallel_mode_initialization(self):
        """Test initialization in parallel mode."""
        tracker = ProgressTracker(total_ips=10, parallel=True)

        assert tracker.total_ips == 10
        assert tracker.parallel is True
        assert tracker._lock is not None

    def test_stages_defined(self):
        """Test that analysis stages are properly defined."""
        expected_stages = [
            "Classification",
            "Local Info",
            "Internet Info",
            "Application Info",
            "Formatting",
            "Writing"
        ]

        assert ProgressTracker.STAGES == expected_stages


class TestOverallProgressUpdates:
    """Test overall progress indicator updates."""

    def test_update_overall_progress_basic(self):
        """Test basic overall progress update."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        tracker.update_overall_progress(5, "192.168.1.5")

        assert tracker.current_ip == 5
        assert tracker.current_ip_address == "192.168.1.5"
        assert tracker.current_stage is None
        assert tracker.stage_progress == 0.0

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

    def test_update_overall_progress_resets_sub_progress(self):
        """Test that overall progress update resets sub-progress."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        # Set sub-progress
        tracker.update_sub_progress("192.168.1.1", "Classification", 0.5)
        assert tracker.current_stage == "Classification"
        assert tracker.stage_progress == 0.5

        # Update overall progress should reset sub-progress
        tracker.update_overall_progress(2, "192.168.1.2")
        assert tracker.current_stage is None
        assert tracker.stage_progress == 0.0


class TestSubProgressUpdates:
    """Test sub-progress tracking for analysis stages."""

    def test_update_sub_progress_basic(self):
        """Test basic sub-progress update."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        tracker.update_sub_progress("192.168.1.1", "Classification", 0.5)

        assert tracker.current_ip_address == "192.168.1.1"
        assert tracker.current_stage == "Classification"
        assert tracker.stage_progress == 0.5

    def test_update_sub_progress_all_stages(self):
        """Test sub-progress updates for all stages."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        for stage in ProgressTracker.STAGES:
            tracker.update_sub_progress("192.168.1.1", stage, 0.75)
            assert tracker.current_stage == stage
            assert tracker.stage_progress == 0.75

    def test_update_sub_progress_clamps_to_valid_range(self):
        """Test that sub-progress is clamped to [0.0, 1.0]."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        # Test values below 0
        tracker.update_sub_progress("192.168.1.1", "Classification", -0.5)
        assert tracker.stage_progress == 0.0

        # Test values above 1
        tracker.update_sub_progress("192.168.1.1", "Classification", 1.5)
        assert tracker.stage_progress == 1.0

        # Test boundary values
        tracker.update_sub_progress("192.168.1.1", "Classification", 0.0)
        assert tracker.stage_progress == 0.0

        tracker.update_sub_progress("192.168.1.1", "Classification", 1.0)
        assert tracker.stage_progress == 1.0


class TestStageTransitions:
    """Test stage start and completion methods."""

    def test_start_stage(self):
        """Test starting an analysis stage."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        tracker.start_stage("192.168.1.1", "Classification")

        assert tracker.current_ip_address == "192.168.1.1"
        assert tracker.current_stage == "Classification"
        assert tracker.stage_progress == 0.0

    def test_complete_stage(self):
        """Test completing an analysis stage."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        tracker.complete_stage("192.168.1.1", "Classification")

        assert tracker.current_ip_address == "192.168.1.1"
        assert tracker.current_stage == "Classification"
        assert tracker.stage_progress == 1.0

    def test_stage_lifecycle(self):
        """Test complete stage lifecycle: start -> progress -> complete."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        # Start stage
        tracker.start_stage("192.168.1.1", "Local Info")
        assert tracker.stage_progress == 0.0

        # Update progress
        tracker.update_sub_progress("192.168.1.1", "Local Info", 0.5)
        assert tracker.stage_progress == 0.5

        # Complete stage
        tracker.complete_stage("192.168.1.1", "Local Info")
        assert tracker.stage_progress == 1.0

    def test_multiple_stages_sequence(self):
        """Test processing multiple stages in sequence."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        ip_address = "192.168.1.1"

        for stage in ProgressTracker.STAGES:
            # Start stage
            tracker.start_stage(ip_address, stage)
            assert tracker.current_stage == stage
            assert tracker.stage_progress == 0.0

            # Complete stage
            tracker.complete_stage(ip_address, stage)
            assert tracker.current_stage == stage
            assert tracker.stage_progress == 1.0


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
        tracker.update_sub_progress("192.168.1.5", "Classification", 0.5)
        tracker.start_stage("192.168.1.5", "Local Info")
        tracker.complete_stage("192.168.1.5", "Local Info")


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

    def test_sub_progress_percentage_calculation(self):
        """Test sub-progress percentage calculations."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        test_values = [0.0, 0.25, 0.5, 0.75, 1.0]

        for progress in test_values:
            tracker.update_sub_progress("192.168.1.1", "Classification", progress)
            assert abs(tracker.stage_progress - progress) < 0.01


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

    def test_stage_with_empty_ip_address(self):
        """Test stage updates with empty IP address."""
        tracker = ProgressTracker(total_ips=10, parallel=False)

        # Should handle empty string
        tracker.update_sub_progress("", "Classification", 0.5)
        assert tracker.current_ip_address == ""
        assert tracker.current_stage == "Classification"
