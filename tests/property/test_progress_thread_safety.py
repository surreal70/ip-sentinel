"""
Property-based tests for progress tracker thread safety.

Feature: progress-indicator-improvements
Tests Properties 7, 8, 9 related to thread safety and non-TTY mode
"""

import sys
from io import StringIO
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from hypothesis import given, settings, strategies as st
from src.ip_sentinel.batch import ProgressTracker


@given(
    total_ips=st.integers(min_value=1, max_value=100),
    num_threads=st.integers(min_value=2, max_value=10),
    completions_per_thread=st.integers(min_value=1, max_value=20)
)
@settings(max_examples=20, deadline=None)
def test_thread_safe_completion_counting(total_ips, num_threads, completions_per_thread):
    """
    Feature: progress-indicator-improvements, Property 7: Thread-Safe Completion Counting
    
    For any set of concurrent mark_completed() calls in parallel mode, the final
    completed_scans value should equal the total number of calls made, with no
    lost updates due to race conditions.
    
    Validates: Requirements 5.2, 5.3
    """
    # Create progress tracker in parallel mode
    tracker = ProgressTracker(total_ips=total_ips, parallel=True)
    
    # Calculate total number of completions
    total_completions = num_threads * completions_per_thread
    expected_completions = min(total_completions, total_ips)
    
    # Define worker function
    def mark_completions():
        """Worker function that marks completions."""
        for _ in range(completions_per_thread):
            tracker.mark_completed()
    
    # Execute concurrent mark_completed calls
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(mark_completions) for _ in range(num_threads)]
        
        # Wait for all threads to complete
        for future in futures:
            future.result()
    
    # Verify final count is exactly what we expect (no lost updates)
    assert tracker.completed_scans == expected_completions, \
        f"After {total_completions} concurrent calls with {num_threads} threads, " \
        f"completed_scans should be {expected_completions}, " \
        f"got {tracker.completed_scans}"
    
    # Verify counter never exceeded total_ips
    assert tracker.completed_scans <= total_ips, \
        f"Completed scans {tracker.completed_scans} should not exceed total {total_ips}"


@given(
    total_ips=st.integers(min_value=1, max_value=100),
    num_threads=st.integers(min_value=2, max_value=10)
)
@settings(max_examples=20, deadline=None)
def test_thread_safe_progress_updates(total_ips, num_threads):
    """
    Property: Concurrent progress updates maintain consistency.
    
    For any set of concurrent update_overall_progress() calls in parallel mode,
    the tracker should maintain consistent state without corruption.
    
    Validates: Requirements 5.1, 5.4
    """
    # Create progress tracker in parallel mode
    tracker = ProgressTracker(total_ips=total_ips, parallel=True)
    
    # Define worker function
    def update_progress(ip_index):
        """Worker function that updates progress."""
        tracker.update_overall_progress(ip_index, f"192.168.1.{ip_index}")
    
    # Execute concurrent progress updates
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Each thread updates with a different IP index
        futures = [
            executor.submit(update_progress, i % total_ips + 1)
            for i in range(num_threads)
        ]
        
        # Wait for all threads to complete
        for future in futures:
            future.result()
    
    # Verify state is consistent (within valid bounds)
    assert 0 <= tracker.current_ip <= total_ips, \
        f"Current IP {tracker.current_ip} should be in range [0, {total_ips}]"
    
    # Verify completed_scans is still 0 (progress updates don't affect completion)
    assert tracker.completed_scans == 0, \
        f"Progress updates should not affect completed_scans, got {tracker.completed_scans}"


@given(
    total_ips=st.integers(min_value=10, max_value=100),
    num_threads=st.integers(min_value=2, max_value=10)
)
@settings(max_examples=20, deadline=None)
def test_thread_safe_mixed_operations(total_ips, num_threads):
    """
    Property: Mixed concurrent operations maintain consistency.
    
    For any mix of concurrent mark_completed() and update_overall_progress()
    calls in parallel mode, the tracker should maintain consistent state.
    
    Validates: Requirements 5.1, 5.2, 5.3, 5.4
    """
    # Create progress tracker in parallel mode
    tracker = ProgressTracker(total_ips=total_ips, parallel=True)
    
    operations_per_thread = 5
    
    # Define worker function with mixed operations
    def mixed_operations(thread_id):
        """Worker function that performs mixed operations."""
        for i in range(operations_per_thread):
            if i % 2 == 0:
                # Even iterations: update progress
                ip_index = (thread_id * operations_per_thread + i) % total_ips + 1
                tracker.update_overall_progress(ip_index, f"192.168.1.{ip_index}")
            else:
                # Odd iterations: mark completed
                tracker.mark_completed()
    
    # Execute concurrent mixed operations
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(mixed_operations, thread_id)
            for thread_id in range(num_threads)
        ]
        
        # Wait for all threads to complete
        for future in futures:
            future.result()
    
    # Calculate expected completions
    # For operations_per_thread=5: indices 0,2,4 are progress updates, 1,3 are completions
    # So 2 completions per thread
    completions_per_thread = operations_per_thread // 2  # 5 // 2 = 2
    expected_completions = min(num_threads * completions_per_thread, total_ips)
    
    # Verify state is consistent
    assert 0 <= tracker.current_ip <= total_ips, \
        f"Current IP {tracker.current_ip} should be in range [0, {total_ips}]"
    
    assert tracker.completed_scans == expected_completions, \
        f"Completed scans should be {expected_completions}, got {tracker.completed_scans}"
    
    assert tracker.completed_scans <= total_ips, \
        f"Completed scans {tracker.completed_scans} should not exceed total {total_ips}"


@given(
    total_ips=st.integers(min_value=1, max_value=100)
)
@settings(max_examples=20, deadline=None)
def test_sequential_mode_no_lock_overhead(total_ips):
    """
    Property: Sequential mode operates without lock overhead.
    
    For any progress tracker in sequential mode (parallel=False), operations
    should work correctly without thread locks.
    
    Validates: Requirements 5.1
    """
    # Create progress tracker in sequential mode
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    
    # Verify no lock is created
    assert tracker._lock is None, \
        "Sequential mode should not create a lock"
    
    # Perform operations
    for i in range(1, min(10, total_ips) + 1):
        tracker.update_overall_progress(i, f"192.168.1.{i}")
        tracker.mark_completed()
    
    # Verify state is correct
    expected_completions = min(10, total_ips)
    assert tracker.completed_scans == expected_completions, \
        f"Completed scans should be {expected_completions}, got {tracker.completed_scans}"


@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_non_tty_mode_suppression(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property 8: Non-TTY Mode Suppression
    
    For any progress state when stdout is not a TTY, calling display_progress()
    should produce no output (no ANSI codes, no progress text).
    
    Validates: Requirements 6.1, 6.2, 6.4
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker.current_ip = current_ip
    tracker.completed_scans = completed
    
    # Capture output with non-TTY mode
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        # Mock isatty to return False (non-TTY mode)
        with patch('sys.stdout.isatty', return_value=False):
            tracker.display_progress()
            output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify no output is produced
    assert output == "", \
        f"Non-TTY mode should produce no output, got: {repr(output)}"
    
    # Verify no ANSI codes in output
    assert '\033' not in output, \
        f"Non-TTY mode should not contain ANSI codes, got: {repr(output)}"
    
    # Verify no progress text in output
    assert "Processing IP" not in output, \
        f"Non-TTY mode should not contain progress text, got: {repr(output)}"
    assert "Completed:" not in output, \
        f"Non-TTY mode should not contain completion text, got: {repr(output)}"


@given(
    total_ips=st.integers(min_value=1, max_value=100),
    parallel=st.booleans()
)
@settings(max_examples=20, deadline=None)
def test_non_tty_complete_no_clearing(total_ips, parallel):
    """
    Property: Non-TTY mode complete() produces no output.
    
    For any progress tracker when stdout is not a TTY, calling complete()
    should produce no output (no ANSI clearing codes).
    
    Validates: Requirements 6.2, 7.4
    """
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=parallel)
    
    # Mark as displayed to simulate that progress was shown
    tracker._displayed = True
    
    # Capture output with non-TTY mode
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        # Mock isatty to return False (non-TTY mode)
        with patch('sys.stdout.isatty', return_value=False):
            tracker.complete()
            output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify no output is produced
    assert output == "", \
        f"Non-TTY mode complete() should produce no output, got: {repr(output)}"
    
    # Verify no ANSI codes in output
    assert '\033' not in output, \
        f"Non-TTY mode complete() should not contain ANSI codes, got: {repr(output)}"


@given(
    total_ips=st.integers(min_value=1, max_value=100),
    num_updates=st.integers(min_value=1, max_value=50)
)
@settings(max_examples=20, deadline=None)
def test_non_tty_state_tracking(total_ips, num_updates):
    """
    Feature: progress-indicator-improvements, Property 9: Non-TTY State Tracking
    
    For any sequence of progress updates when stdout is not a TTY, the internal
    state (current_ip, completed_scans) should be updated correctly even though
    no display output is produced.
    
    Validates: Requirements 6.5
    """
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    
    # Perform updates in non-TTY mode
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        with patch('sys.stdout.isatty', return_value=False):
            # Perform a sequence of progress updates
            for i in range(1, min(num_updates, total_ips) + 1):
                # Update overall progress
                tracker.update_overall_progress(i, f"192.168.1.{i}")
                
                # Verify current_ip is updated
                assert tracker.current_ip == i, \
                    f"After update {i}, current_ip should be {i}, got {tracker.current_ip}"
                
                # Mark completed
                tracker.mark_completed()
                
                # Verify completed_scans is updated
                assert tracker.completed_scans == i, \
                    f"After completion {i}, completed_scans should be {i}, " \
                    f"got {tracker.completed_scans}"
            
            # Verify no output was produced
            output = sys.stdout.getvalue()
            assert output == "", \
                f"Non-TTY mode should produce no output, got: {repr(output)}"
    finally:
        sys.stdout = old_stdout
    
    # Verify final state is correct
    expected_updates = min(num_updates, total_ips)
    assert tracker.current_ip == expected_updates, \
        f"Final current_ip should be {expected_updates}, got {tracker.current_ip}"
    assert tracker.completed_scans == expected_updates, \
        f"Final completed_scans should be {expected_updates}, " \
        f"got {tracker.completed_scans}"


@given(
    total_ips=st.integers(min_value=1, max_value=100),
    parallel=st.booleans()
)
@settings(max_examples=20, deadline=None)
def test_non_tty_state_consistency(total_ips, parallel):
    """
    Property: Non-TTY mode maintains state consistency.
    
    For any progress tracker in non-TTY mode, internal state should remain
    consistent across multiple operations without display output.
    
    Validates: Requirements 6.5
    """
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=parallel)
    
    # Perform mixed operations in non-TTY mode
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        with patch('sys.stdout.isatty', return_value=False):
            # Update progress to midpoint
            midpoint = total_ips // 2
            tracker.update_overall_progress(midpoint, f"192.168.1.{midpoint}")
            
            # Mark some completions
            num_completions = min(5, total_ips)
            for _ in range(num_completions):
                tracker.mark_completed()
            
            # Verify no output was produced
            output = sys.stdout.getvalue()
            assert output == "", \
                f"Non-TTY mode should produce no output, got: {repr(output)}"
    finally:
        sys.stdout = old_stdout
    
    # Verify state is consistent
    assert tracker.current_ip == midpoint, \
        f"Current IP should be {midpoint}, got {tracker.current_ip}"
    assert tracker.completed_scans == num_completions, \
        f"Completed scans should be {num_completions}, got {tracker.completed_scans}"
    assert tracker.total_ips == total_ips, \
        f"Total IPs should remain {total_ips}, got {tracker.total_ips}"
    
    # Verify state is within valid bounds
    assert 0 <= tracker.current_ip <= total_ips, \
        f"Current IP {tracker.current_ip} should be in range [0, {total_ips}]"
    assert 0 <= tracker.completed_scans <= total_ips, \
        f"Completed scans {tracker.completed_scans} should be in range [0, {total_ips}]"
