"""
Property-based tests for progress completion counter.

Feature: progress-indicator-improvements, Property 3: Completion Increment Property
Feature: progress-indicator-improvements, Property 11: Completion Counter Bounds
Validates: Requirements 3.1, 3.2, 3.3
"""

from hypothesis import given, settings, strategies as st
from src.ip_sentinel.batch import ProgressTracker


@given(
    total_ips=st.integers(min_value=1, max_value=1024),
    num_completions=st.integers(min_value=0, max_value=1024)
)
@settings(max_examples=20, deadline=None)
def test_completion_increment_property(total_ips, num_completions):
    """
    Property 3: Completion Increment Property

    For any sequence of mark_completed() calls, the completed_scans counter
    should equal the number of calls made, regardless of whether the scans
    succeeded or failed.

    Validates: Requirements 3.2, 3.3
    """
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Initial state should be 0
    assert tracker.completed_scans == 0, \
        f"Initial completed_scans should be 0, got {tracker.completed_scans}"

    # Call mark_completed() num_completions times
    expected_completions = min(num_completions, total_ips)
    for i in range(num_completions):
        tracker.mark_completed()

    # Verify completed_scans equals the number of calls (clamped to total_ips)
    assert tracker.completed_scans == expected_completions, \
        f"After {num_completions} calls, completed_scans should be {expected_completions}, " \
        f"got {tracker.completed_scans}"


@given(
    total_ips=st.integers(min_value=1, max_value=100)
)
@settings(max_examples=20, deadline=None)
def test_completion_counter_sequential_accuracy(total_ips):
    """
    Property: Sequential completion tracking maintains accuracy.

    For any batch size, marking completions sequentially from 1 to total_ips
    should maintain accurate completed_scans values at each step.

    Validates: Requirements 3.2, 3.3
    """
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Mark completions sequentially
    for i in range(1, total_ips + 1):
        tracker.mark_completed()

        # Verify current state
        assert tracker.completed_scans == i, \
            f"After {i} completions, completed_scans should be {i}, " \
            f"got {tracker.completed_scans}"
        assert tracker.total_ips == total_ips, \
            f"Total IPs should remain {total_ips}, got {tracker.total_ips}"


@given(
    total_ips=st.integers(min_value=1, max_value=1024),
    current_ip=st.integers(min_value=0, max_value=1024),
    completed=st.integers(min_value=0, max_value=1024)
)
@settings(max_examples=20, deadline=None)
def test_completion_counter_bounds(total_ips, current_ip, completed):
    """
    Property 11: Completion Counter Bounds

    For any progress state, the completed_scans counter should always be
    in the range [0, total_ips] and should never exceed total_ips.

    Validates: Requirements 3.1
    """
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Update overall progress
    if current_ip <= total_ips:
        tracker.update_overall_progress(current_ip, f"192.168.1.{current_ip}")

    # Mark completions
    for _ in range(completed):
        tracker.mark_completed()

    # Verify bounds
    assert tracker.completed_scans >= 0, \
        f"Completed scans should never be negative, got {tracker.completed_scans}"
    assert tracker.completed_scans <= total_ips, \
        f"Completed scans {tracker.completed_scans} should not exceed total {total_ips}"

    # Verify completed_scans is an integer
    assert isinstance(tracker.completed_scans, int), \
        f"Completed scans should be an integer, got {type(tracker.completed_scans)}"


@given(
    total_ips=st.integers(min_value=1, max_value=100),
    excess_calls=st.integers(min_value=1, max_value=50)
)
@settings(max_examples=20, deadline=None)
def test_completion_counter_clamping(total_ips, excess_calls):
    """
    Property: Completion counter is clamped to total_ips.

    For any batch size, calling mark_completed() more times than total_ips
    should clamp the counter at total_ips, not exceed it.

    Validates: Requirements 3.1
    """
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Call mark_completed() more times than total_ips
    num_calls = total_ips + excess_calls
    for _ in range(num_calls):
        tracker.mark_completed()

    # Verify counter is clamped at total_ips
    assert tracker.completed_scans == total_ips, \
        f"After {num_calls} calls with total_ips={total_ips}, " \
        f"completed_scans should be clamped at {total_ips}, " \
        f"got {tracker.completed_scans}"


@given(
    total_ips=st.integers(min_value=1, max_value=1024)
)
@settings(max_examples=20, deadline=None)
def test_completion_counter_initialization(total_ips):
    """
    Property: Completion counter is initialized to 0.

    For any batch size, a newly created ProgressTracker should have
    completed_scans initialized to 0.

    Validates: Requirements 3.1
    """
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Verify initial state
    assert tracker.completed_scans == 0, \
        f"Initial completed_scans should be 0, got {tracker.completed_scans}"
    assert isinstance(tracker.completed_scans, int), \
        f"Completed scans should be an integer, got {type(tracker.completed_scans)}"


@given(
    total_ips=st.integers(min_value=1, max_value=100)
)
@settings(max_examples=20, deadline=None)
def test_completion_independent_of_current_progress(total_ips):
    """
    Property: Completion counter is independent of current progress.

    For any batch size, the completed_scans counter should be independent
    of the current_ip value. Updating overall progress should not affect
    completed_scans, and marking completions should not affect current_ip.

    Validates: Requirements 3.1, 3.2
    """
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)

    # Update overall progress
    mid_point = total_ips // 2
    tracker.update_overall_progress(mid_point, f"192.168.1.{mid_point}")

    # Verify completed_scans is still 0
    assert tracker.completed_scans == 0, \
        f"Updating overall progress should not affect completed_scans, " \
        f"got {tracker.completed_scans}"

    # Mark some completions
    num_completions = min(5, total_ips)
    for _ in range(num_completions):
        tracker.mark_completed()

    # Verify current_ip is unchanged
    assert tracker.current_ip == mid_point, \
        f"Marking completions should not affect current_ip, " \
        f"expected {mid_point}, got {tracker.current_ip}"

    # Verify completed_scans is correct
    assert tracker.completed_scans == num_completions, \
        f"Completed scans should be {num_completions}, got {tracker.completed_scans}"
