"""
Property-based tests for progress display format properties.

Feature: progress-indicator-improvements
Tests Properties 1, 2, 4, 5, 6 related to display format
"""

import sys
from io import StringIO
from unittest.mock import patch
from hypothesis import given, settings, strategies as st
from src.ip_sentinel.batch import ProgressTracker


def capture_display_output(tracker):
    """
    Capture display output for testing.
    
    Args:
        tracker: ProgressTracker instance
        
    Returns:
        Captured output string
    """
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        # Mock isatty to return True for testing
        with patch('sys.stdout.isatty', return_value=True):
            tracker.display_progress()
            output = sys.stdout.getvalue()
        return output
    finally:
        sys.stdout = old_stdout


@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_no_sub_progress_display(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property 1: No Sub-Progress Display
    
    For any progress state (current IP, completed scans, total IPs), the display
    output should not contain any stage names (Classification, Local Info,
    Internet Info, Application Info, Formatting, Writing) or stage-specific
    progress bars.
    
    Validates: Requirements 1.1, 1.3
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker.current_ip = current_ip
    tracker.completed_scans = completed
    
    # Capture display output
    output = capture_display_output(tracker)
    
    # Define stage names that should NOT appear in output
    stage_names = [
        "Classification",
        "Local Info",
        "Internet Info",
        "Application Info",
        "Formatting",
        "Writing"
    ]
    
    # Verify no stage names appear in output
    for stage_name in stage_names:
        assert stage_name not in output, \
            f"Stage name '{stage_name}' should not appear in display output"
    
    # Verify no stage-specific progress indicators (e.g., "[====]")
    # The overall progress bar is allowed, but not multiple stage bars
    lines = output.strip().split('\n')
    
    # Should have exactly 2 lines
    if len(lines) >= 2:
        # Check that stage-related text doesn't appear
        for line in lines:
            # Stage names should not be in any line
            for stage_name in stage_names:
                assert stage_name not in line, \
                    f"Stage name '{stage_name}' found in line: {line}"



@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_completion_counter_format(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property 2: Completion Counter Format
    
    For any progress state, the display output should contain a completion
    indicator in the exact format "Completed: X/Y scans" where X is the number
    of completed scans and Y is the total number of IPs.
    
    Validates: Requirements 3.1, 3.4
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker.current_ip = current_ip
    tracker.completed_scans = completed
    
    # Capture display output
    output = capture_display_output(tracker)
    
    # Expected completion counter format
    expected_format = f"Completed: {completed}/{total_ips} scans"
    
    # Verify the exact format appears in output
    assert expected_format in output, \
        f"Expected completion format '{expected_format}' not found in output:\n{output}"
    
    # Verify it appears on its own line (second line)
    lines = output.strip().split('\n')
    assert len(lines) >= 2, \
        f"Output should have at least 2 lines, got {len(lines)}"
    
    # The completion counter should be on the second line
    completion_line = lines[1] if len(lines) > 1 else ""
    assert expected_format in completion_line, \
        f"Completion counter should be on second line. Got: {completion_line}"



@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_two_line_display_format(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property 4: Two-Line Display Format
    
    For any progress state in TTY mode, the display output should consist of
    exactly two lines: the first line containing the overall progress indicator
    with format "Processing IP X/Y [progress_bar] Z%" and the second line
    containing the completion indicator with format "Completed: X/Y scans".
    
    Validates: Requirements 4.1, 4.2, 4.3, 3.6
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker.current_ip = current_ip
    tracker.completed_scans = completed
    
    # Capture display output
    output = capture_display_output(tracker)
    
    # Split into lines and filter out empty lines
    lines = [line for line in output.split('\n') if line.strip()]
    
    # Verify exactly 2 lines
    assert len(lines) == 2, \
        f"Display should have exactly 2 lines, got {len(lines)}: {lines}"
    
    # Verify first line format: "Processing IP X/Y [progress_bar] Z%"
    first_line = lines[0]
    assert "Processing IP" in first_line, \
        f"First line should contain 'Processing IP', got: {first_line}"
    assert f"{current_ip}/{total_ips}" in first_line, \
        f"First line should contain '{current_ip}/{total_ips}', got: {first_line}"
    assert "[" in first_line and "]" in first_line, \
        f"First line should contain progress bar with brackets, got: {first_line}"
    assert "%" in first_line, \
        f"First line should contain percentage, got: {first_line}"
    
    # Verify second line format: "Completed: X/Y scans"
    second_line = lines[1]
    expected_completion = f"Completed: {completed}/{total_ips} scans"
    assert expected_completion == second_line, \
        f"Second line should be '{expected_completion}', got: {second_line}"



@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=1, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_ansi_escape_code_usage(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property 5: ANSI Escape Code Usage
    
    For any progress update in TTY mode after initial display, the output should
    contain ANSI escape codes for cursor repositioning (moving up 2 lines:
    '\033[2A') and line clearing ('\033[K') to update the display in place.
    
    Validates: Requirements 2.3, 4.4
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create progress tracker
    tracker = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker.current_ip = current_ip
    tracker.completed_scans = completed
    
    # First display - should not have ANSI codes (initial display)
    first_output = capture_display_output(tracker)
    
    # Mark as displayed to simulate subsequent update
    tracker._displayed = True
    
    # Second display - should have ANSI codes for clearing
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        with patch('sys.stdout.isatty', return_value=True):
            tracker.display_progress()
            second_output = sys.stdout.getvalue()
    finally:
        sys.stdout = old_stdout
    
    # Verify ANSI escape codes are present in second output
    # '\033[2A' - move cursor up 2 lines
    assert '\033[2A' in second_output, \
        f"Second display should contain cursor up escape code '\\033[2A'"
    
    # '\033[K' - clear line
    assert '\033[K' in second_output, \
        f"Second display should contain line clear escape code '\\033[K'"
    
    # Verify first output does NOT contain these codes (initial display)
    assert '\033[2A' not in first_output, \
        f"First display should not contain cursor up escape code"



@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
@settings(max_examples=20, deadline=None)
def test_format_consistency_across_modes(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property 6: Format Consistency Across Modes
    
    For any progress state, the display output format should be identical
    whether the ProgressTracker is initialized with parallel=True or
    parallel=False.
    
    Validates: Requirements 4.5
    """
    # Ensure values are within valid bounds
    current_ip = min(current_ip, total_ips)
    completed = min(completed, total_ips)
    
    # Create sequential mode tracker
    tracker_seq = ProgressTracker(total_ips=total_ips, parallel=False)
    tracker_seq.current_ip = current_ip
    tracker_seq.completed_scans = completed
    
    # Create parallel mode tracker
    tracker_par = ProgressTracker(total_ips=total_ips, parallel=True)
    tracker_par.current_ip = current_ip
    tracker_par.completed_scans = completed
    
    # Capture display output from both modes
    output_seq = capture_display_output(tracker_seq)
    output_par = capture_display_output(tracker_par)
    
    # Verify outputs are identical
    assert output_seq == output_par, \
        f"Display format should be identical in sequential and parallel modes.\n" \
        f"Sequential output:\n{output_seq}\n" \
        f"Parallel output:\n{output_par}"
    
    # Verify both have exactly 2 lines
    lines_seq = [line for line in output_seq.split('\n') if line.strip()]
    lines_par = [line for line in output_par.split('\n') if line.strip()]
    
    assert len(lines_seq) == 2, \
        f"Sequential mode should have 2 lines, got {len(lines_seq)}"
    assert len(lines_par) == 2, \
        f"Parallel mode should have 2 lines, got {len(lines_par)}"
    
    # Verify line-by-line consistency
    for i, (line_seq, line_par) in enumerate(zip(lines_seq, lines_par)):
        assert line_seq == line_par, \
            f"Line {i+1} differs between modes:\n" \
            f"Sequential: {line_seq}\n" \
            f"Parallel: {line_par}"
