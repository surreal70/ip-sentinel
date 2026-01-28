# Requirements Document

## Introduction

This document specifies improvements to the progress indicator system in the IP-Sentinel batch processing module. The current implementation displays both overall progress and detailed per-IP sub-progress indicators. The improvements will simplify the display by removing sub-progress tracking, ensuring indicators stay at the bottom of the terminal, and adding a completion counter to show how many scans have finished.

## Glossary

- **Progress_Tracker**: The class responsible for displaying and updating progress indicators during batch processing operations
- **Overall_Progress**: The primary progress indicator showing current IP being processed out of total IPs (e.g., "Processing IP 5/10")
- **Sub_Progress**: The detailed stage-by-stage progress display for individual IP addresses (e.g., "Classification [====] Local Info [=>  ]")
- **Completion_Indicator**: A new progress indicator showing the count of completed scans versus total scans
- **Terminal_Bottom**: The lowest visible line in the terminal window where progress indicators should be displayed
- **ANSI_Escape_Codes**: Special character sequences used to control terminal cursor positioning and display clearing
- **Sequential_Mode**: Processing mode where IP addresses are analyzed one at a time in order
- **Parallel_Mode**: Processing mode where multiple IP addresses are analyzed concurrently using thread pools

## Requirements

### Requirement 1: Remove Sub-Progress Display

**User Story:** As a user running batch IP scans, I want a cleaner progress display without detailed stage information, so that the terminal output is less cluttered and easier to read.

#### Acceptance Criteria

1. THE Progress_Tracker SHALL NOT display sub-progress indicators for individual IP analysis stages
2. THE Progress_Tracker SHALL NOT track or update stage-specific progress (Classification, Local Info, Internet Info, Application Info, Formatting, Writing)
3. WHEN displaying progress, THE Progress_Tracker SHALL NOT show stage progress bars for individual IP addresses
4. THE Progress_Tracker SHALL remove all methods related to sub-progress tracking (start_stage, complete_stage, update_sub_progress)
5. THE Progress_Tracker SHALL remove the STAGES class attribute that defines analysis stages

### Requirement 2: Bottom-Anchored Progress Display

**User Story:** As a user monitoring batch processing, I want the progress indicators to stay at the bottom of my terminal, so that I can see the current status without scrolling and the display remains stable.

#### Acceptance Criteria

1. WHEN displaying progress updates, THE Progress_Tracker SHALL position indicators at the bottom of the terminal
2. WHEN progress updates occur, THE Progress_Tracker SHALL update indicators in place without causing screen scrolling
3. THE Progress_Tracker SHALL use ANSI escape codes to maintain cursor position at the terminal bottom
4. WHILE batch processing is active, THE Progress_Tracker SHALL ensure progress indicators remain visible at the bottom of the terminal
5. WHEN the terminal receives new output, THE Progress_Tracker SHALL reposition indicators to the terminal bottom

### Requirement 3: Completion Counter Display

**User Story:** As a user running batch scans, I want to see how many scans have completed versus the total, so that I can understand both current progress and completion status.

#### Acceptance Criteria

1. THE Progress_Tracker SHALL display a completion indicator showing completed scans versus total scans
2. WHEN a scan completes successfully, THE Progress_Tracker SHALL increment the completed scan counter
3. WHEN a scan fails, THE Progress_Tracker SHALL increment the completed scan counter
4. THE Progress_Tracker SHALL display the completion indicator in the format "Completed: X/Y scans"
5. THE Progress_Tracker SHALL update the completion indicator in real-time as scans finish
6. THE Progress_Tracker SHALL display both the overall progress indicator and completion indicator at the terminal bottom

### Requirement 4: Simplified Progress Display Format

**User Story:** As a user viewing batch processing progress, I want a clear and simple two-line display, so that I can quickly understand the current status without visual clutter.

#### Acceptance Criteria

1. THE Progress_Tracker SHALL display exactly two lines of progress information
2. THE Progress_Tracker SHALL display the overall progress indicator on the first line showing current IP being processed
3. THE Progress_Tracker SHALL display the completion indicator on the second line showing completed scans
4. WHEN updating progress, THE Progress_Tracker SHALL refresh both lines in place without adding new lines
5. THE Progress_Tracker SHALL maintain consistent formatting across sequential and parallel processing modes

### Requirement 5: Thread-Safe Progress Updates

**User Story:** As a system running parallel batch processing, I want progress updates to be thread-safe, so that concurrent operations don't corrupt the display or cause race conditions.

#### Acceptance Criteria

1. WHEN parallel mode is enabled, THE Progress_Tracker SHALL use thread locks for all progress updates
2. WHEN multiple threads update progress simultaneously, THE Progress_Tracker SHALL serialize updates to prevent display corruption
3. THE Progress_Tracker SHALL maintain accurate completion counts in parallel mode
4. THE Progress_Tracker SHALL ensure atomic updates to both overall progress and completion counters
5. WHEN displaying progress in parallel mode, THE Progress_Tracker SHALL prevent interleaved output from multiple threads

### Requirement 6: Non-Interactive Mode Handling

**User Story:** As a system administrator running batch scans in automated scripts, I want progress indicators to be disabled in non-interactive mode, so that log files and piped output remain clean.

#### Acceptance Criteria

1. WHEN stdout is not a TTY, THE Progress_Tracker SHALL NOT display progress indicators
2. WHEN running in non-interactive mode, THE Progress_Tracker SHALL skip all ANSI escape code operations
3. THE Progress_Tracker SHALL detect TTY status using sys.stdout.isatty()
4. WHEN progress tracking completes in non-interactive mode, THE Progress_Tracker SHALL NOT attempt to clear display
5. THE Progress_Tracker SHALL maintain internal progress state even when display is disabled

### Requirement 7: Clean Progress Completion

**User Story:** As a user completing a batch scan, I want the progress indicators to be cleanly removed when processing finishes, so that the terminal is ready for the next command without leftover display artifacts.

#### Acceptance Criteria

1. WHEN batch processing completes, THE Progress_Tracker SHALL clear all progress indicators from the terminal
2. THE Progress_Tracker SHALL use ANSI escape codes to remove both progress lines
3. WHEN the complete() method is called, THE Progress_Tracker SHALL restore the terminal to a clean state
4. THE Progress_Tracker SHALL only clear display if progress was previously shown
5. WHEN running in non-interactive mode, THE Progress_Tracker SHALL skip display clearing operations

### Requirement 8: Backward Compatibility

**User Story:** As a developer maintaining the IP-Sentinel codebase, I want the Progress_Tracker API changes to be compatible with existing BatchProcessor code, so that minimal refactoring is required.

#### Acceptance Criteria

1. THE Progress_Tracker SHALL maintain the update_overall_progress() method signature
2. THE Progress_Tracker SHALL maintain the complete() method signature
3. THE Progress_Tracker SHALL maintain the __init__() method signature with total_ips and parallel parameters
4. THE BatchProcessor SHALL NOT require changes to its core processing logic
5. THE Progress_Tracker SHALL automatically track completion counts without requiring explicit completion notifications from BatchProcessor
