# Design Document: Progress Indicator Improvements

## Overview

This design document describes the improvements to the `ProgressTracker` class in the IP-Sentinel batch processing system. The improvements focus on simplifying the progress display by removing detailed sub-progress tracking, ensuring indicators remain anchored at the bottom of the terminal, and adding a completion counter to show scan completion status.

The current implementation displays two lines: an overall progress bar and a detailed sub-progress line showing individual IP analysis stages. The improved design will maintain two lines but replace the sub-progress with a completion counter, providing clearer and more useful information to users.

## Architecture

### Current Architecture

The current `ProgressTracker` class maintains:
- Overall progress: Current IP index out of total IPs
- Sub-progress: Detailed stage tracking for individual IPs (Classification, Local Info, Internet Info, etc.)
- Thread-safe updates using locks in parallel mode
- ANSI escape code-based terminal manipulation

### Improved Architecture

The improved `ProgressTracker` will maintain:
- Overall progress: Current IP being processed out of total IPs
- Completion counter: Number of completed scans (successful + failed) out of total
- Thread-safe updates using locks in parallel mode
- Bottom-anchored display using ANSI escape codes
- Simplified internal state (no stage tracking)

### Key Changes

1. **Remove sub-progress tracking**: Eliminate all stage-related methods and state
2. **Add completion tracking**: Track completed scans separately from current progress
3. **Simplify display logic**: Two-line display with overall progress and completion counter
4. **Maintain thread safety**: Preserve lock-based synchronization for parallel mode

## Components and Interfaces

### ProgressTracker Class

**Modified Attributes:**
```python
class ProgressTracker:
    def __init__(self, total_ips: int, parallel: bool = False):
        self.total_ips: int           # Total number of IPs to process
        self.parallel: bool            # Enable thread-safe mode
        self.current_ip: int           # Current IP index (0-based internally, 1-based for display)
        self.current_ip_address: Optional[str]  # Current IP address being processed
        self.completed_scans: int      # NEW: Count of completed scans
        self._lock: Optional[threading.Lock]  # Thread lock for parallel mode
        self._displayed: bool          # Track if progress has been displayed
```

**Removed Attributes:**
- `current_stage: Optional[str]` - No longer tracking stages
- `stage_progress: float` - No longer tracking stage progress
- `STAGES: List[str]` - No longer need stage definitions

**Modified Methods:**

```python
def update_overall_progress(self, current: int, ip_address: Optional[str] = None) -> None:
    """
    Update overall progress indicator.
    
    Args:
        current: Current IP number (1-indexed)
        ip_address: Optional IP address being processed
    """
    # Thread-safe update of current IP and address
    # Does NOT increment completed_scans
    
def mark_completed(self) -> None:
    """
    Mark the current scan as completed (success or failure).
    Increments the completed_scans counter.
    """
    # Thread-safe increment of completed_scans
    # Triggers display update
    
def display_progress(self) -> None:
    """
    Display current progress to console.
    Shows two lines:
    1. Overall progress: "Processing IP X/Y [=====>    ] Z%"
    2. Completion: "Completed: X/Y scans"
    """
    # Check if TTY
    # Clear previous display (2 lines)
    # Display overall progress bar
    # Display completion counter
    # Flush output
    
def complete(self) -> None:
    """
    Mark progress tracking as complete and clear display.
    """
    # Clear 2 lines if displayed
    # Log completion
```

**Removed Methods:**
- `update_sub_progress()` - No longer tracking sub-progress
- `_update_sub_progress_unsafe()` - No longer needed
- `start_stage()` - No longer tracking stages
- `complete_stage()` - No longer tracking stages

### BatchProcessor Integration

**Modified Methods:**

The `BatchProcessor` class will need minimal changes:

```python
def _process_single_ip(self, ip: Union[IPv4Address, IPv6Address], ip_str: str) -> tuple:
    """Process a single IP address (sequential mode)."""
    # Analyze IP
    result = self.analyzer.analyze(ip_str)
    
    # Format output
    formatter = self._get_formatter()
    formatted_output = formatter.format_result(result)
    
    # Write result
    self.file_manager.write_result(ip, formatted_output)
    
    # Mark as completed (NEW)
    self.progress_tracker.mark_completed()
    
    return result, formatted_output

def _process_single_ip_parallel(self, ip: Union[IPv4Address, IPv6Address], idx: int, total_ips: int) -> tuple:
    """Process a single IP address (parallel mode)."""
    ip_str = str(ip)
    
    # Update overall progress
    self.progress_tracker.update_overall_progress(idx, ip_str)
    
    # Analyze IP
    result = self.analyzer.analyze(ip_str)
    
    # Format output
    formatter = self._get_formatter()
    formatted_output = formatter.format_result(result)
    
    # Write result
    self.file_manager.write_result(ip, formatted_output)
    
    # Mark as completed (NEW)
    self.progress_tracker.mark_completed()
    
    return result, formatted_output
```

**Exception Handling:**

In both `_process_sequential()` and `_process_parallel()`, when an exception occurs during IP processing, the code should still call `mark_completed()` to ensure the completion counter is accurate:

```python
try:
    result, formatted_output = self._process_single_ip(ip, ip_str)
    # ... success handling ...
except Exception as e:
    # ... error handling ...
    self.progress_tracker.mark_completed()  # NEW: Mark as completed even on failure
    failed += 1
```

## Data Models

### Progress State

The progress tracker maintains the following state:

```python
@dataclass
class ProgressState:
    """Internal state representation (conceptual, not implemented as separate class)"""
    total_ips: int              # Total IPs to process
    current_ip: int             # Current IP index (0-based)
    current_ip_address: str     # Current IP being processed
    completed_scans: int        # Number of completed scans
    parallel: bool              # Parallel mode flag
    displayed: bool             # Whether progress has been displayed
```

### Display Format

**Line 1 - Overall Progress:**
```
Processing IP {current}/{total} [=====>    ] {percent}%
```

**Line 2 - Completion Counter:**
```
Completed: {completed}/{total} scans
```

**Example Output:**
```
Processing IP 5/10 [=========>              ] 50.0%
Completed: 3/10 scans
```

Note: The completion counter may lag behind the current IP because a scan is marked complete only after all processing (analysis, formatting, writing) finishes.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*


### Property 1: No Sub-Progress Display

*For any* progress state (current IP, completed scans, total IPs), the display output should not contain any stage names (Classification, Local Info, Internet Info, Application Info, Formatting, Writing) or stage-specific progress bars.

**Validates: Requirements 1.1, 1.3**

### Property 2: Completion Counter Format

*For any* progress state, the display output should contain a completion indicator in the exact format "Completed: X/Y scans" where X is the number of completed scans and Y is the total number of IPs.

**Validates: Requirements 3.1, 3.4**

### Property 3: Completion Increment Property

*For any* sequence of mark_completed() calls, the completed_scans counter should equal the number of calls made, regardless of whether the scans succeeded or failed.

**Validates: Requirements 3.2, 3.3**

### Property 4: Two-Line Display Format

*For any* progress state in TTY mode, the display output should consist of exactly two lines: the first line containing the overall progress indicator with format "Processing IP X/Y [progress_bar] Z%" and the second line containing the completion indicator with format "Completed: X/Y scans".

**Validates: Requirements 4.1, 4.2, 4.3, 3.6**

### Property 5: ANSI Escape Code Usage

*For any* progress update in TTY mode after initial display, the output should contain ANSI escape codes for cursor repositioning (moving up 2 lines: '\033[2A') and line clearing ('\033[K') to update the display in place.

**Validates: Requirements 2.3, 4.4**

### Property 6: Format Consistency Across Modes

*For any* progress state, the display output format should be identical whether the ProgressTracker is initialized with parallel=True or parallel=False.

**Validates: Requirements 4.5**

### Property 7: Thread-Safe Completion Counting

*For any* set of concurrent mark_completed() calls in parallel mode, the final completed_scans value should equal the total number of calls made, with no lost updates due to race conditions.

**Validates: Requirements 5.2, 5.3**

### Property 8: Non-TTY Mode Suppression

*For any* progress state when stdout is not a TTY, calling display_progress() should produce no output (no ANSI codes, no progress text).

**Validates: Requirements 6.1, 6.2, 6.4**

### Property 9: Non-TTY State Tracking

*For any* sequence of progress updates when stdout is not a TTY, the internal state (current_ip, completed_scans) should be updated correctly even though no display output is produced.

**Validates: Requirements 6.5**

### Property 10: Conditional Display Clearing

*For any* ProgressTracker instance, calling complete() should only produce ANSI escape codes for clearing if display_progress() was previously called and stdout is a TTY.

**Validates: Requirements 7.1, 7.4**

### Property 11: Completion Counter Bounds

*For any* progress state, the completed_scans counter should always be in the range [0, total_ips] and should never exceed total_ips.

**Validates: Requirements 3.1** (implicit correctness requirement)

## Error Handling

### Non-TTY Detection

The ProgressTracker must gracefully handle non-interactive environments:

```python
def display_progress(self):
    if not sys.stdout.isatty():
        return  # Skip all display operations
    # ... display logic ...
```

### Thread Safety

In parallel mode, all state updates must be protected by locks:

```python
def mark_completed(self):
    if self._lock:
        with self._lock:
            self._mark_completed_unsafe()
    else:
        self._mark_completed_unsafe()
```

### Bounds Checking

The completion counter must be clamped to valid ranges:

```python
def _mark_completed_unsafe(self):
    self.completed_scans = min(self.completed_scans + 1, self.total_ips)
    self.display_progress()
```

### Exception Safety

Display operations should not raise exceptions that interrupt batch processing:

```python
def display_progress(self):
    try:
        if not sys.stdout.isatty():
            return
        # ... display logic ...
        sys.stdout.flush()
    except Exception as e:
        logger.warning(f"Failed to display progress: {e}")
        # Continue without display
```

## Testing Strategy

### Dual Testing Approach

The implementation will use both unit tests and property-based tests:

- **Unit tests**: Verify specific examples, edge cases (0 IPs, 1 IP, max IPs), API compatibility, and error conditions
- **Property tests**: Verify universal properties across all valid progress states and concurrent operations

### Property-Based Testing

We will use the **Hypothesis** library for Python to implement property-based tests. Each correctness property will be implemented as a property-based test with a minimum of 100 iterations.

**Test Configuration:**
```python
from hypothesis import given, settings
import hypothesis.strategies as st

@settings(max_examples=100)
@given(
    total_ips=st.integers(min_value=1, max_value=1000),
    current_ip=st.integers(min_value=0, max_value=1000),
    completed=st.integers(min_value=0, max_value=1000)
)
def test_property_X(total_ips, current_ip, completed):
    """
    Feature: progress-indicator-improvements, Property X: [Property Title]
    """
    # Test implementation
```

**Tag Format**: Each property test will include a docstring comment:
```
Feature: progress-indicator-improvements, Property {number}: {property_text}
```

### Unit Testing Focus

Unit tests will cover:

1. **API Compatibility**: Verify method signatures match requirements (8.1, 8.2, 8.3)
2. **Structural Requirements**: Verify removed methods/attributes don't exist (1.2, 1.4, 1.5)
3. **Edge Cases**:
   - Zero IPs to process
   - Single IP to process
   - Maximum batch size (1024 IPs)
   - Completion counter at boundary (0, total_ips)
4. **Error Conditions**:
   - Non-TTY environment handling
   - Exception during display operations
   - Invalid progress values (negative, exceeding total)
5. **Integration**: Verify BatchProcessor integration works correctly

### Property Testing Focus

Property tests will cover:

1. **Display Format Properties** (Properties 1, 2, 4, 5, 6)
2. **Counter Properties** (Properties 3, 11)
3. **Thread Safety** (Property 7)
4. **Mode Handling** (Properties 8, 9, 10)

### Test Organization

```
tests/
├── unit/
│   ├── test_progress_tracker_api.py       # API compatibility tests
│   ├── test_progress_tracker_structure.py # Structural requirement tests
│   ├── test_progress_tracker_edge_cases.py # Edge case tests
│   └── test_batch_processor_integration.py # Integration tests
└── property/
    ├── test_progress_display_properties.py  # Display format properties
    ├── test_progress_counter_properties.py  # Counter properties
    └── test_progress_concurrency_properties.py # Thread safety properties
```

### Mock Strategy

For testing display output without actual terminal interaction:

```python
from io import StringIO
import sys

def capture_display_output(tracker):
    """Capture display output for testing."""
    old_stdout = sys.stdout
    sys.stdout = StringIO()
    try:
        tracker.display_progress()
        output = sys.stdout.getvalue()
        return output
    finally:
        sys.stdout = old_stdout
```

For testing TTY detection:

```python
from unittest.mock import patch

@patch('sys.stdout.isatty', return_value=False)
def test_non_tty_mode(mock_isatty):
    # Test non-TTY behavior
```

### Concurrency Testing

For thread safety properties, use concurrent execution:

```python
from concurrent.futures import ThreadPoolExecutor

def test_concurrent_mark_completed():
    tracker = ProgressTracker(total_ips=100, parallel=True)
    
    def mark_complete():
        tracker.mark_completed()
    
    # Execute 50 concurrent mark_completed calls
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(mark_complete) for _ in range(50)]
        for future in futures:
            future.result()
    
    # Verify final count is exactly 50
    assert tracker.completed_scans == 50
```
