# Implementation Plan: Progress Indicator Improvements

## Overview

This implementation plan refactors the `ProgressTracker` class in `src/ip_sentinel/batch.py` to simplify progress display by removing sub-progress tracking, adding a completion counter, and ensuring indicators stay at the bottom of the terminal. The changes maintain backward compatibility with the `BatchProcessor` class while improving user experience.

## Tasks

- [x] 1. Refactor ProgressTracker class to remove sub-progress tracking
  - Remove the `STAGES` class attribute
  - Remove `current_stage` and `stage_progress` instance attributes
  - Remove `start_stage()`, `complete_stage()`, `update_sub_progress()`, and `_update_sub_progress_unsafe()` methods
  - Update `__init__()` to remove stage-related initialization
  - Update `_update_overall_progress_unsafe()` to remove stage state clearing
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [x] 1.1 Write unit tests for structural changes
  - Test that removed methods and attributes don't exist
  - Test that ProgressTracker can be instantiated without errors
  - _Requirements: 1.2, 1.4, 1.5_

- [x] 2. Add completion counter tracking to ProgressTracker
  - [x] 2.1 Add `completed_scans` attribute initialized to 0 in `__init__()`
    - Initialize as integer counter
    - _Requirements: 3.1_
  
  - [x] 2.2 Implement `mark_completed()` method with thread safety
    - Create public `mark_completed()` method
    - Create private `_mark_completed_unsafe()` helper
    - Implement lock-based synchronization for parallel mode
    - Increment `completed_scans` counter with bounds checking (max: total_ips)
    - Call `display_progress()` after incrementing
    - _Requirements: 3.2, 3.3, 5.1, 5.4_
  
  - [x] 2.3 Write property test for completion counter increment
    - **Property 3: Completion Increment Property**
    - **Validates: Requirements 3.2, 3.3**
  
  - [x] 2.4 Write property test for completion counter bounds
    - **Property 11: Completion Counter Bounds**
    - **Validates: Requirements 3.1**

- [x] 3. Update display_progress() method for new two-line format
  - [x] 3.1 Modify display logic to show only overall progress and completion counter
    - Keep TTY check at the beginning
    - Update line clearing to handle 2 lines (keep existing '\033[2A\033[K')
    - Build overall progress line (keep existing format)
    - Build completion counter line: "Completed: {completed_scans}/{total_ips} scans"
    - Write both lines with newlines
    - Remove all sub-progress display logic
    - _Requirements: 3.1, 3.4, 4.1, 4.2, 4.3, 4.4_
  
  - [x] 3.2 Write property test for no sub-progress display
    - **Property 1: No Sub-Progress Display**
    - **Validates: Requirements 1.1, 1.3**
  
  - [x] 3.3 Write property test for completion counter format
    - **Property 2: Completion Counter Format**
    - **Validates: Requirements 3.1, 3.4**
  
  - [x] 3.4 Write property test for two-line display format
    - **Property 4: Two-Line Display Format**
    - **Validates: Requirements 4.1, 4.2, 4.3, 3.6**
  
  - [x] 3.5 Write property test for ANSI escape code usage
    - **Property 5: ANSI Escape Code Usage**
    - **Validates: Requirements 2.3, 4.4**
  
  - [x] 3.6 Write property test for format consistency across modes
    - **Property 6: Format Consistency Across Modes**
    - **Validates: Requirements 4.5**

- [x] 4. Update complete() method for two-line clearing
  - Modify ANSI escape sequence to clear 2 lines: '\033[2A\033[K\033[K'
  - Keep existing TTY and _displayed checks
  - _Requirements: 7.1, 7.4_

- [x] 4.1 Write property test for conditional display clearing
  - **Property 10: Conditional Display Clearing**
  - **Validates: Requirements 7.1, 7.4**

- [x] 5. Add exception safety to display operations
  - Wrap display_progress() body in try-except block
  - Log warnings on display failures without interrupting processing
  - Ensure flush() is called in finally block if TTY
  - _Requirements: Error Handling_

- [x] 6. Update BatchProcessor integration
  - [x] 6.1 Modify _process_single_ip() to call mark_completed()
    - Add `self.progress_tracker.mark_completed()` after successful write
    - Remove all `start_stage()` and `complete_stage()` calls
    - _Requirements: 8.4_
  
  - [x] 6.2 Modify _process_single_ip_parallel() to call mark_completed()
    - Add `self.progress_tracker.mark_completed()` after successful write
    - Remove all `start_stage()` and `complete_stage()` calls
    - _Requirements: 8.4_
  
  - [x] 6.3 Update exception handling in _process_sequential()
    - Add `self.progress_tracker.mark_completed()` in except block
    - Ensure completion is tracked even on failure
    - _Requirements: 3.3_
  
  - [x] 6.4 Update exception handling in _process_parallel()
    - Add `self.progress_tracker.mark_completed()` in except block
    - Ensure completion is tracked even on failure
    - _Requirements: 3.3_

- [x] 6.5 Write integration tests for BatchProcessor
  - Test sequential processing with progress tracking
  - Test parallel processing with progress tracking
  - Test that completion counter matches total IPs processed
  - Test that failures are counted in completion
  - _Requirements: 8.4_

- [x] 7. Checkpoint - Ensure all tests pass
  - Run all unit tests and property tests
  - Verify no regressions in batch processing
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Add property tests for thread safety
  - [x] 8.1 Write property test for thread-safe completion counting
    - **Property 7: Thread-Safe Completion Counting**
    - **Validates: Requirements 5.2, 5.3**
  
  - [x] 8.2 Write property test for non-TTY mode suppression
    - **Property 8: Non-TTY Mode Suppression**
    - **Validates: Requirements 6.1, 6.2, 6.4**
  
  - [x] 8.3 Write property test for non-TTY state tracking
    - **Property 9: Non-TTY State Tracking**
    - **Validates: Requirements 6.5**

- [x] 9. Add unit tests for API compatibility
  - [x] 9.1 Test update_overall_progress() method signature
    - Verify method exists with correct parameters
    - _Requirements: 8.1_
  
  - [x] 9.2 Test complete() method signature
    - Verify method exists with correct parameters
    - _Requirements: 8.2_
  
  - [x] 9.3 Test __init__() method signature
    - Verify constructor accepts total_ips and parallel parameters
    - _Requirements: 8.3_
  
  - [x] 9.4 Test edge cases
    - Test with 0 IPs
    - Test with 1 IP
    - Test with maximum batch size (1024 IPs)
    - Test completion counter at boundaries
    - _Requirements: 3.1, 3.2_

- [x] 10. Final checkpoint - Verify all requirements met
  - Run complete test suite (unit + property tests)
  - Manually test with sample batch processing
  - Verify display appears correctly in terminal
  - Verify non-TTY mode works correctly
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- All tasks are required for comprehensive implementation
- Each task references specific requirements for traceability
- Property tests validate universal correctness properties using Hypothesis library
- Unit tests validate specific examples, edge cases, and API compatibility
- The implementation maintains backward compatibility with existing BatchProcessor code
- Thread safety is preserved for parallel processing mode
