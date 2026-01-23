"""
Property-based tests for progress indicator accuracy.

Feature: ip-intelligence-analyzer, Property 28: Progress Indicator Accuracy
Validates: Requirements 11.11
"""

from hypothesis import given, settings, strategies as st
from src.ip_sentinel.batch import ProgressTracker


@given(
    total_ips=st.integers(min_value=1, max_value=1024),
    current_ip=st.integers(min_value=1, max_value=1024)
)
@settings(max_examples=100, deadline=None)
def test_progress_indicator_reflects_current_and_total(total_ips, current_ip):
    """
    Property 28: Progress Indicator Accuracy

    For any batch processing operation, the overall progress indicator should
    accurately reflect the current IP number and total count, updating after
    each IP is processed.

    Validates: Requirements 11.11
    """
    # Ensure current_ip doesn't exceed total_ips
    if current_ip > total_ips:
        current_ip = total_ips

    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Update progress
    tracker.update_overall_progress(current_ip, f"192.168.1.{current_ip}")

    # Verify progress state
    assert tracker.total_ips == total_ips, \
        f"Total IPs should be {total_ips}, got {tracker.total_ips}"
    assert tracker.current_ip == current_ip, \
        f"Current IP should be {current_ip}, got {tracker.current_ip}"

    # Verify progress percentage calculation
    expected_percent = (current_ip / total_ips * 100) if total_ips > 0 else 0
    actual_percent = (tracker.current_ip / tracker.total_ips * 100) if tracker.total_ips > 0 else 0

    assert abs(actual_percent - expected_percent) < 0.01, \
        f"Progress percentage should be {expected_percent:.2f}%, got {actual_percent:.2f}%"


@given(
    total_ips=st.integers(min_value=1, max_value=100)
)
@settings(max_examples=100, deadline=None)
def test_progress_updates_sequentially(total_ips):
    """
    Property: Sequential progress updates maintain accuracy.

    For any batch size, updating progress sequentially from 1 to total_ips
    should maintain accurate current_ip values at each step.

    Validates: Requirements 11.11
    """
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Update progress sequentially
    for i in range(1, total_ips + 1):
        tracker.update_overall_progress(i, f"192.168.1.{i}")

        # Verify current state
        assert tracker.current_ip == i, \
            f"After update {i}, current_ip should be {i}, got {tracker.current_ip}"
        assert tracker.total_ips == total_ips, \
            f"Total IPs should remain {total_ips}, got {tracker.total_ips}"


@given(
    total_ips=st.integers(min_value=1, max_value=100),
    stage=st.sampled_from(ProgressTracker.STAGES),
    progress=st.floats(min_value=0.0, max_value=1.0)
)
@settings(max_examples=100, deadline=None)
def test_sub_progress_tracking_accuracy(total_ips, stage, progress):
    """
    Property: Sub-progress tracking accurately reflects stage and progress.

    For any IP address and analysis stage, the sub-progress indicator should
    accurately reflect the current stage and progress within that stage.

    Validates: Requirements 11.12
    """
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    ip_address = "192.168.1.1"

    # Update sub-progress
    tracker.update_sub_progress(ip_address, stage, progress)

    # Verify sub-progress state
    assert tracker.current_ip_address == ip_address, \
        f"Current IP address should be {ip_address}, got {tracker.current_ip_address}"
    assert tracker.current_stage == stage, \
        f"Current stage should be {stage}, got {tracker.current_stage}"

    # Progress should be clamped to [0.0, 1.0]
    expected_progress = max(0.0, min(1.0, progress))
    assert abs(tracker.stage_progress - expected_progress) < 0.01, \
        f"Stage progress should be {expected_progress:.2f}, got {tracker.stage_progress:.2f}"


@given(
    total_ips=st.integers(min_value=1, max_value=50)
)
@settings(max_examples=100, deadline=None)
def test_stage_completion_sequence(total_ips):
    """
    Property: Stage completion follows expected sequence.

    For any IP address, completing stages in sequence should maintain
    accurate stage tracking throughout the analysis.

    Validates: Requirements 11.12
    """
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    ip_address = "192.168.1.1"

    # Complete stages in sequence
    for stage in ProgressTracker.STAGES:
        # Start stage
        tracker.start_stage(ip_address, stage)
        assert tracker.current_stage == stage, \
            f"Current stage should be {stage} after start"
        assert tracker.stage_progress == 0.0, \
            f"Stage progress should be 0.0 at start, got {tracker.stage_progress}"

        # Complete stage
        tracker.complete_stage(ip_address, stage)
        assert tracker.current_stage == stage, \
            f"Current stage should still be {stage} after completion"
        assert tracker.stage_progress == 1.0, \
            f"Stage progress should be 1.0 after completion, got {tracker.stage_progress}"


@given(
    total_ips=st.integers(min_value=1, max_value=1024)
)
@settings(max_examples=100, deadline=None)
def test_parallel_mode_initialization(total_ips):
    """
    Property: Parallel mode creates thread-safe tracker.

    For any batch size, initializing a progress tracker in parallel mode
    should create a thread-safe tracker with proper locking mechanisms.

    Validates: Requirements 11.15
    """
    # Create parallel tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=True)

    # Verify parallel mode is enabled
    assert tracker.parallel is True, "Parallel mode should be enabled"
    assert tracker._lock is not None, "Lock should be initialized in parallel mode"

    # Create sequential tracker
    tracker_seq = ProgressTracker(total_ips=total_ips, parallel=False)

    # Verify sequential mode
    assert tracker_seq.parallel is False, "Parallel mode should be disabled"
    assert tracker_seq._lock is None, "Lock should not be initialized in sequential mode"


@given(
    total_ips=st.integers(min_value=1, max_value=100),
    current_ip=st.integers(min_value=0, max_value=100)
)
@settings(max_examples=100, deadline=None)
def test_progress_bounds_validation(total_ips, current_ip):
    """
    Property: Progress values are always within valid bounds.

    For any progress update, the current IP should never exceed total IPs,
    and progress percentages should always be between 0 and 100.

    Validates: Requirements 11.11
    """
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Update with potentially out-of-bounds value
    tracker.update_overall_progress(current_ip, f"192.168.1.{current_ip}")

    # Verify bounds
    assert tracker.current_ip >= 0, "Current IP should never be negative"
    assert tracker.current_ip <= total_ips, \
        f"Current IP {tracker.current_ip} should not exceed total {total_ips}"

    # Calculate percentage
    if total_ips > 0:
        percent = (tracker.current_ip / tracker.total_ips * 100)
        assert 0 <= percent <= 100, \
            f"Progress percentage {percent:.2f}% should be between 0 and 100"
