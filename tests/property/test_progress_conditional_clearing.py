"""
Property-based tests for conditional display clearing.

Feature: progress-indicator-improvements
Tests Property 10 related to display clearing behavior
"""

import sys
from io import StringIO
from unittest.mock import patch
from hypothesis import given, settings, strategies as st
from src.ip_sentinel.batch import ProgressTracker


@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000),
    display_before_complete=st.booleans(),
    is_tty=st.booleans()
)
@settings(max_examples=20, deadline=None)
def test_conditional_display_clearing(total_ips, current_ip, completed, display_before_complete, is_tty):
    """
    Feature: progress-indicator-improvements, Property 10: Conditional Display Clearing
    
    For any ProgressTracker instance, calling complete() should only produce
    ANSI escape codes for clearing if display_progress() was previously called
    and stdout is a TTY.
    
    Validates: Requirements 7.1, 7.4
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker.current_ip = current_ip
    tracker.completed_scans = completed
    
    # Optionally display progress before completing
    if display_before_complete:
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            with patch('sys.stdout.isatty', return_value=is_tty):
                tracker.display_progress()
        finally:
            sys.stdout = old_stdout
    
    # Capture complete() output
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        with patch('sys.stdout.isatty', return_value=is_tty):
            tracker.complete()
            complete_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Determine if clearing should occur
    should_clear = display_before_complete and is_tty
    
    # ANSI escape codes for clearing 2 lines: '\033[2A\033[K\033[K'
    # '\033[2A' - move cursor up 2 lines
    # '\033[K' - clear line (appears twice for 2 lines)
    has_clear_codes = '\033[2A' in complete_output and '\033[K' in complete_output
    
    if should_clear:
        # If display was shown and TTY is active, clearing codes should be present
        assert has_clear_codes, \
            f"complete() should produce ANSI clear codes when display was shown and TTY is active.\n" \
            f"display_before_complete={display_before_complete}, is_tty={is_tty}\n" \
            f"Output: {repr(complete_output)}"
    else:
        # If display was not shown OR TTY is not active, no clearing codes
        assert not has_clear_codes, \
            f"complete() should NOT produce ANSI clear codes when display was not shown or TTY is not active.\n" \
            f"display_before_complete={display_before_complete}, is_tty={is_tty}\n" \
            f"Output: {repr(complete_output)}"
    
    # Additional verification: check _displayed flag behavior
    if display_before_complete and is_tty:
        # _displayed should have been set to True by display_progress()
        # (we can't directly verify this after complete() as it's internal state)
        pass
    else:
        # If display was never shown or not TTY, _displayed should be False
        # and complete() should not attempt clearing
        pass


@given(
    total_ips=st.integers(min_value=1, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_complete_without_display(total_ips):
    """
    Feature: progress-indicator-improvements, Property 10: Conditional Display Clearing
    
    Specific test case: calling complete() without ever calling display_progress()
    should not produce any ANSI escape codes, regardless of TTY status.
    
    Validates: Requirements 7.1, 7.4
    """
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    
    # Call complete() without ever calling display_progress()
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        # Test with TTY=True
        with patch('sys.stdout.isatty', return_value=True):
            tracker.complete()
            output_tty = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Should not contain ANSI clear codes
    assert '\033[2A' not in output_tty, \
        f"complete() should not produce clear codes when display was never shown (TTY=True)"
    assert '\033[K' not in output_tty, \
        f"complete() should not produce clear codes when display was never shown (TTY=True)"
    
    # Reset tracker for non-TTY test
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        # Test with TTY=False
        with patch('sys.stdout.isatty', return_value=False):
            tracker.complete()
            output_no_tty = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Should not contain ANSI clear codes
    assert '\033[2A' not in output_no_tty, \
        f"complete() should not produce clear codes when display was never shown (TTY=False)"
    assert '\033[K' not in output_no_tty, \
        f"complete() should not produce clear codes when display was never shown (TTY=False)"


@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_complete_with_display_tty(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property 10: Conditional Display Clearing
    
    Specific test case: calling complete() after display_progress() in TTY mode
    should produce ANSI escape codes for clearing 2 lines.
    
    Validates: Requirements 7.1, 7.4
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker.current_ip = current_ip
    tracker.completed_scans = completed
    
    # Display progress in TTY mode
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        with patch('sys.stdout.isatty', return_value=True):
            tracker.display_progress()
    finally:
        sys.stdout = old_stdout
    
    # Call complete() in TTY mode
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        with patch('sys.stdout.isatty', return_value=True):
            tracker.complete()
            complete_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Should contain ANSI clear codes for 2 lines
    assert '\033[2A' in complete_output, \
        f"complete() should contain cursor up code '\\033[2A' after display in TTY mode"
    assert '\033[K' in complete_output, \
        f"complete() should contain line clear code '\\033[K' after display in TTY mode"
    
    # Verify it clears 2 lines: '\033[2A\033[K\033[K'
    # The exact sequence should move up 2 lines and clear both
    assert complete_output.count('\033[K') >= 2, \
        f"complete() should clear 2 lines (2 occurrences of '\\033[K'), got {complete_output.count('\033[K')}"


@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_complete_with_display_no_tty(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property 10: Conditional Display Clearing
    
    Specific test case: calling complete() after display_progress() in non-TTY mode
    should NOT produce ANSI escape codes (display_progress() would have been skipped).
    
    Validates: Requirements 7.1, 7.4
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker.current_ip = current_ip
    tracker.completed_scans = completed
    
    # Attempt to display progress in non-TTY mode (should be skipped)
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        with patch('sys.stdout.isatty', return_value=False):
            tracker.display_progress()
            display_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify display was skipped (no output)
    assert display_output == "", \
        f"display_progress() should produce no output in non-TTY mode"
    
    # Call complete() in non-TTY mode
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        with patch('sys.stdout.isatty', return_value=False):
            tracker.complete()
            complete_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Should not contain ANSI clear codes
    assert '\033[2A' not in complete_output, \
        f"complete() should not contain cursor up code in non-TTY mode"
    assert '\033[K' not in complete_output, \
        f"complete() should not contain line clear code in non-TTY mode"
