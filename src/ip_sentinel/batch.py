"""
Batch processing infrastructure for IP-Sentinel.

This module provides batch analysis capabilities for multiple IP addresses
from CIDR networks with support for sequential and parallel processing.
"""

import logging
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_network
from pathlib import Path
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class BatchSizeExceededError(Exception):
    """Raised when batch size exceeds the maximum allowed limit."""
    pass


class InvalidOutputFormatError(Exception):
    """Raised when batch mode is used with invalid output format."""
    pass


class OutputFolderError(Exception):
    """Raised when there are issues with the output folder."""
    pass


@dataclass
class BatchResult:
    """Container for batch processing results."""

    total_ips: int
    successful: int
    failed: int
    start_time: datetime
    end_time: datetime
    results: Dict[str, any]  # IP string -> AnalysisResult
    errors: Dict[str, str]  # IP string -> error message
    output_files: List[str]

    @property
    def duration(self) -> float:
        """Get batch processing duration in seconds."""
        return (self.end_time - self.start_time).total_seconds()


class ProgressTracker:
    """
    Provides real-time progress feedback for batch operations.

    This class manages both overall progress (current IP / total IPs) and
    sub-progress for individual IP analysis stages. It supports both
    sequential and parallel processing modes with thread-safe updates.
    """

    # Analysis stages for sub-progress tracking
    STAGES = [
        "Classification",
        "Local Info",
        "Internet Info",
        "Application Info",
        "Formatting",
        "Writing"
    ]

    def __init__(self, total_ips: int, parallel: bool = False):
        """
        Initialize the progress tracker.

        Args:
            total_ips: Total number of IP addresses to process
            parallel: Enable thread-safe mode for parallel processing
        """
        self.total_ips = total_ips
        self.parallel = parallel
        self.current_ip = 0
        self.current_ip_address: Optional[str] = None
        self.current_stage: Optional[str] = None
        self.stage_progress: float = 0.0

        # Thread safety for parallel mode
        if parallel:
            self._lock = threading.Lock()
        else:
            self._lock = None

        # Track if we've displayed progress (for clearing)
        self._displayed = False

        logger.debug(
            f"ProgressTracker initialized: total_ips={total_ips}, "
            f"parallel={parallel}"
        )

    def update_overall_progress(self, current: int, ip_address: Optional[str] = None):
        """
        Update overall progress indicator.

        Args:
            current: Current IP number (1-indexed)
            ip_address: Optional IP address being processed
        """
        if self._lock:
            with self._lock:
                self._update_overall_progress_unsafe(current, ip_address)
        else:
            self._update_overall_progress_unsafe(current, ip_address)

    def _update_overall_progress_unsafe(self, current: int, ip_address: Optional[str] = None):
        """Internal method to update overall progress without locking."""
        # Clamp current to valid range [0, total_ips]
        self.current_ip = max(0, min(current, self.total_ips))
        self.current_ip_address = ip_address
        self.current_stage = None
        self.stage_progress = 0.0
        self.display_progress()

    def update_sub_progress(
            self,
            ip_address: str,
            stage: str,
            progress: float = 1.0):
        """
        Update sub-progress for individual IP analysis stage.

        Args:
            ip_address: IP address being processed
            stage: Analysis stage name
            progress: Progress within stage (0.0 to 1.0)
        """
        if self._lock:
            with self._lock:
                self._update_sub_progress_unsafe(ip_address, stage, progress)
        else:
            self._update_sub_progress_unsafe(ip_address, stage, progress)

    def _update_sub_progress_unsafe(
            self,
            ip_address: str,
            stage: str,
            progress: float = 1.0):
        """Internal method to update sub-progress without locking."""
        self.current_ip_address = ip_address
        self.current_stage = stage
        self.stage_progress = max(0.0, min(1.0, progress))
        self.display_progress()

    def display_progress(self):
        """
        Display current progress to console.

        Shows overall progress bar and sub-progress for current IP.
        """
        if not sys.stdout.isatty():
            # Don't display progress bars in non-interactive mode
            return

        # Clear previous progress display
        if self._displayed:
            # Move cursor up 2 lines and clear
            sys.stdout.write('\033[2A\033[K')

        # Calculate overall progress percentage
        overall_percent = (self.current_ip / self.total_ips * 100) if self.total_ips > 0 else 0

        # Build overall progress bar
        bar_width = 40
        filled = int(bar_width * self.current_ip / self.total_ips) if self.total_ips > 0 else 0
        bar = '=' * filled + '>' + ' ' * (bar_width - filled - 1)

        # Display overall progress
        overall_line = (
            f"Processing IP {self.current_ip}/{self.total_ips} "
            f"[{bar}] {overall_percent:.1f}%"
        )
        sys.stdout.write(overall_line + '\n')

        # Display sub-progress if available
        if self.current_ip_address and self.current_stage:
            # Build stage progress indicators
            stage_indicators = []
            for stage in self.STAGES:
                if stage == self.current_stage:
                    # Current stage - show progress
                    if self.stage_progress >= 1.0:
                        stage_indicators.append(f"{stage} [====]")
                    else:
                        progress_chars = int(4 * self.stage_progress)
                        stage_bar = '=' * progress_chars + '>' + ' ' * (3 - progress_chars)
                        stage_indicators.append(f"{stage} [{stage_bar}]")
                elif self.STAGES.index(stage) < self.STAGES.index(self.current_stage):
                    # Completed stages
                    stage_indicators.append(f"{stage} [====]")
                else:
                    # Future stages
                    stage_indicators.append(f"{stage} [    ]")

            sub_line = f"  {self.current_ip_address}: {' '.join(stage_indicators[:3])}"
            sys.stdout.write(sub_line + '\n')
        else:
            # No sub-progress, just show IP address
            if self.current_ip_address:
                sub_line = f"  {self.current_ip_address}: Starting analysis..."
            else:
                sub_line = "  Initializing..."
            sys.stdout.write(sub_line + '\n')

        sys.stdout.flush()
        self._displayed = True

    def complete(self):
        """
        Mark progress tracking as complete and clear display.
        """
        if self._displayed and sys.stdout.isatty():
            # Move cursor up 2 lines and clear
            sys.stdout.write('\033[2A\033[K\033[K')
            sys.stdout.flush()

        logger.info(
            f"Progress tracking completed: {self.current_ip}/{self.total_ips} "
            f"IPs processed"
        )

    def start_stage(self, ip_address: str, stage: str):
        """
        Mark the start of an analysis stage.

        Args:
            ip_address: IP address being processed
            stage: Stage name
        """
        self.update_sub_progress(ip_address, stage, 0.0)

    def complete_stage(self, ip_address: str, stage: str):
        """
        Mark the completion of an analysis stage.

        Args:
            ip_address: IP address being processed
            stage: Stage name
        """
        self.update_sub_progress(ip_address, stage, 1.0)


class FileOutputManager:
    """
    Manages file creation and organization for batch results.

    This class handles output folder creation, filename sanitization,
    and file writing with proper error handling. Thread-safe for parallel
    processing.
    """

    def __init__(self, output_folder: str, format_type: str):
        """
        Initialize the file output manager.

        Args:
            output_folder: Path to output folder
            format_type: Output format ('json' or 'html')

        Raises:
            InvalidOutputFormatError: If format_type is not 'json' or 'html'
        """
        if format_type not in ['json', 'html']:
            raise InvalidOutputFormatError(
                f"Batch mode requires JSON or HTML output format, got: {format_type}"
            )

        self.output_folder = Path(output_folder)
        self.format_type = format_type
        self.extension = f".{format_type}"

        # Thread lock for file writing operations
        self._write_lock = threading.Lock()

        logger.debug(
            f"FileOutputManager initialized: folder={
                self.output_folder}, format={
                self.format_type}")

    def create_output_folder(self):
        """
        Create output folder if it doesn't exist.

        Raises:
            OutputFolderError: If folder creation fails
        """
        try:
            self.output_folder.mkdir(parents=True, exist_ok=True)
            logger.info(f"Output folder ready: {self.output_folder}")
        except Exception as e:
            error_msg = f"Failed to create output folder {self.output_folder}: {e}"
            logger.error(error_msg)
            raise OutputFolderError(error_msg) from e

    def validate_output_folder(self) -> bool:
        """
        Validate that output folder exists and is writable.

        Returns:
            True if folder is valid and writable

        Raises:
            OutputFolderError: If folder is not valid or writable
        """
        if not self.output_folder.exists():
            raise OutputFolderError(
                f"Output folder does not exist: {
                    self.output_folder}")

        if not self.output_folder.is_dir():
            raise OutputFolderError(
                f"Output path is not a directory: {
                    self.output_folder}")

        # Test write permissions by creating a temporary file
        test_file = self.output_folder / ".write_test"
        try:
            test_file.touch()
            test_file.unlink()
            logger.debug(f"Output folder is writable: {self.output_folder}")
            return True
        except Exception as e:
            error_msg = f"Output folder is not writable: {self.output_folder}: {e}"
            logger.error(error_msg)
            raise OutputFolderError(error_msg) from e

    def generate_filename(
            self,
            ip: Union[IPv4Address, IPv6Address]) -> str:
        """
        Generate sanitized filename for an IP address.

        Filename sanitization rules:
        - IPv4: Replace dots with underscores (e.g., 192.168.1.1 -> 192_168_1_1.json)
        - IPv6: Replace colons with underscores, compress consecutive underscores
                (e.g., 2001:db8::1 -> 2001_db8__1.json)
        - Add appropriate extension based on format

        Args:
            ip: IP address object

        Returns:
            Sanitized filename with extension
        """
        ip_str = str(ip)

        if isinstance(ip, IPv4Address):
            # Replace dots with underscores for IPv4
            sanitized = ip_str.replace('.', '_')
        else:
            # Replace colons with underscores for IPv6
            sanitized = ip_str.replace(':', '_')

        # Add extension
        filename = f"{sanitized}{self.extension}"

        logger.debug(f"Generated filename for {ip_str}: {filename}")
        return filename

    def get_output_path(self, ip: Union[IPv4Address, IPv6Address]) -> Path:
        """
        Get full output path for an IP address.

        Args:
            ip: IP address object

        Returns:
            Full path to output file
        """
        filename = self.generate_filename(ip)
        return self.output_folder / filename

    def write_result(
            self,
            ip: Union[IPv4Address,
                      IPv6Address],
            content: str):
        """
        Write analysis result to file.

        Thread-safe operation using internal lock.

        Args:
            ip: IP address object
            content: Formatted content to write

        Raises:
            OutputFolderError: If file writing fails
        """
        output_path = self.get_output_path(ip)

        # Use lock for thread-safe file writing
        with self._write_lock:
            try:
                output_path.write_text(content, encoding='utf-8')
                logger.debug(f"Wrote result for {ip} to {output_path}")
            except Exception as e:
                error_msg = f"Failed to write result for {ip} to {output_path}: {e}"
                logger.error(error_msg)
                raise OutputFolderError(error_msg) from e


class BatchProcessor:
    """
    Manages batch analysis of multiple IP addresses from CIDR networks.

    This class handles CIDR expansion, batch size validation, progress tracking,
    and coordination of analysis for multiple IP addresses.
    """

    MAX_BATCH_SIZE = 1024

    def __init__(
            self,
            analyzer,
            output_folder: str,
            format_type: str,
            parallel: bool = False):
        """
        Initialize the batch processor.

        Args:
            analyzer: IPAnalyzer instance for performing analysis
            output_folder: Path to output folder for results
            format_type: Output format ('json' or 'html')
            parallel: Enable parallel processing (default: False)

        Raises:
            InvalidOutputFormatError: If format_type is not 'json' or 'html'
        """
        self.analyzer = analyzer
        self.parallel = parallel

        # Initialize file output manager
        self.file_manager = FileOutputManager(output_folder, format_type)
        self.format_type = format_type

        # Progress tracker will be initialized when processing starts
        self.progress_tracker: Optional[ProgressTracker] = None

        logger.info(
            f"BatchProcessor initialized: parallel={
                parallel}, format={format_type}")

    def expand_cidr(
            self,
            cidr: str) -> List[Union[IPv4Address, IPv6Address]]:
        """
        Expand CIDR network notation to individual IP addresses.

        Args:
            cidr: CIDR notation string (e.g., "192.168.1.0/24")

        Returns:
            List of IP address objects

        Raises:
            ValueError: If CIDR notation is invalid
        """
        try:
            network = ip_network(cidr, strict=False)
            ip_list = list(network.hosts())

            # For /31 and /32 (IPv4) or /127 and /128 (IPv6) networks,
            # hosts() returns empty list, so use all addresses
            if not ip_list:
                ip_list = list(network)

            logger.info(
                f"Expanded CIDR {cidr} to {
                    len(ip_list)} IP addresses")
            return ip_list

        except ValueError as e:
            error_msg = f"Invalid CIDR notation: {cidr}: {e}"
            logger.error(error_msg)
            raise ValueError(error_msg) from e

    def validate_batch_size(
            self,
            ip_list: List[Union[IPv4Address,
                                IPv6Address]]) -> bool:
        """
        Validate that batch size doesn't exceed maximum limit.

        Args:
            ip_list: List of IP addresses to validate

        Returns:
            True if batch size is valid

        Raises:
            BatchSizeExceededError: If batch size exceeds MAX_BATCH_SIZE
        """
        batch_size = len(ip_list)

        if batch_size > self.MAX_BATCH_SIZE:
            error_msg = (
                f"Batch size {batch_size} exceeds maximum allowed limit of "
                f"{self.MAX_BATCH_SIZE} IP addresses. Please use a smaller CIDR range."
            )
            logger.error(error_msg)
            raise BatchSizeExceededError(error_msg)

        logger.info(
            f"Batch size validated: {batch_size} IPs (limit: {
                self.MAX_BATCH_SIZE})")
        return True

    def process_cidr(self, cidr: str) -> BatchResult:
        """
        Process all IP addresses in a CIDR network.

        This method expands the CIDR notation, validates batch size,
        and processes each IP address.

        Args:
            cidr: CIDR notation string

        Returns:
            BatchResult containing processing statistics and results

        Raises:
            ValueError: If CIDR notation is invalid
            BatchSizeExceededError: If batch size exceeds limit
            InvalidOutputFormatError: If output format is invalid
            OutputFolderError: If output folder operations fail
        """
        logger.info("=" * 80)
        logger.info(f"Starting batch processing for CIDR: {cidr}")
        logger.info("=" * 80)

        start_time = datetime.now()

        # Expand CIDR to IP list
        ip_list = self.expand_cidr(cidr)

        # Validate batch size
        self.validate_batch_size(ip_list)

        # Process IP list
        result = self.process_ip_list(ip_list)

        # Update timing
        result.start_time = start_time
        result.end_time = datetime.now()

        logger.info("=" * 80)
        logger.info(
            f"Batch processing completed: {
                result.successful}/{
                result.total_ips} successful")
        logger.info(f"Duration: {result.duration:.2f} seconds")
        logger.info("=" * 80)

        return result

    def process_ip_list(
            self,
            ip_list: List[Union[IPv4Address,
                                IPv6Address]]) -> BatchResult:
        """
        Process a list of IP addresses.

        Supports both sequential and parallel processing modes.

        Args:
            ip_list: List of IP address objects to process

        Returns:
            BatchResult containing processing statistics and results
        """
        # Create output folder
        self.file_manager.create_output_folder()
        self.file_manager.validate_output_folder()

        total_ips = len(ip_list)
        successful = 0
        failed = 0
        results = {}
        errors = {}
        output_files = []

        # Initialize progress tracker
        self.progress_tracker = ProgressTracker(total_ips, self.parallel)

        # Thread-safe counters for parallel mode
        if self.parallel:
            results_lock = threading.Lock()
            counter_lock = threading.Lock()
        else:
            results_lock = None
            counter_lock = None

        logger.info(f"Processing {total_ips} IP addresses (parallel={self.parallel})...")

        if self.parallel:
            # Parallel processing using ThreadPoolExecutor
            successful, failed, results, errors, output_files = self._process_parallel(
                ip_list, results_lock, counter_lock
            )
        else:
            # Sequential processing
            successful, failed, results, errors, output_files = self._process_sequential(
                ip_list
            )

        # Complete progress tracking
        self.progress_tracker.complete()

        return BatchResult(
            total_ips=total_ips,
            successful=successful,
            failed=failed,
            start_time=datetime.now(),  # Will be updated by caller
            end_time=datetime.now(),  # Will be updated by caller
            results=results,
            errors=errors,
            output_files=output_files
        )

    def _process_sequential(
            self,
            ip_list: List[Union[IPv4Address,
                                IPv6Address]]) -> tuple:
        """
        Process IP addresses sequentially.

        Args:
            ip_list: List of IP addresses to process

        Returns:
            Tuple of (successful, failed, results, errors, output_files)
        """
        successful = 0
        failed = 0
        results = {}
        errors = {}
        output_files = []
        total_ips = len(ip_list)

        for idx, ip in enumerate(ip_list, 1):
            ip_str = str(ip)

            # Update overall progress
            self.progress_tracker.update_overall_progress(idx, ip_str)

            logger.info(f"Processing IP {idx}/{total_ips}: {ip_str}")

            try:
                # Process single IP
                result, formatted_output = self._process_single_ip(ip, ip_str)

                # Track success
                results[ip_str] = result
                output_files.append(str(self.file_manager.get_output_path(ip)))
                successful += 1

                logger.info(f"Successfully processed {ip_str}")

            except Exception as e:
                # Track failure
                error_msg = f"Failed to process {ip_str}: {e}"
                logger.error(error_msg)
                errors[ip_str] = str(e)
                failed += 1

        return successful, failed, results, errors, output_files

    def _process_parallel(
            self,
            ip_list: List[Union[IPv4Address,
                                IPv6Address]],
            results_lock: threading.Lock,
            counter_lock: threading.Lock) -> tuple:
        """
        Process IP addresses in parallel using ThreadPoolExecutor.

        Args:
            ip_list: List of IP addresses to process
            results_lock: Lock for thread-safe results updates
            counter_lock: Lock for thread-safe counter updates

        Returns:
            Tuple of (successful, failed, results, errors, output_files)
        """
        successful = 0
        failed = 0
        results = {}
        errors = {}
        output_files = []
        total_ips = len(ip_list)

        # Determine optimal number of workers based on system resources
        # Use min of: CPU count, total IPs, or max of 10 workers
        import os
        max_workers = min(os.cpu_count() or 4, total_ips, 10)

        logger.info(f"Using {max_workers} worker threads for parallel processing")

        # Create thread pool
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_ip = {}
            for idx, ip in enumerate(ip_list, 1):
                future = executor.submit(
                    self._process_single_ip_parallel,
                    ip,
                    idx,
                    total_ips
                )
                future_to_ip[future] = (ip, idx)

            # Process completed tasks
            for future in as_completed(future_to_ip):
                ip, idx = future_to_ip[future]
                ip_str = str(ip)

                try:
                    # Get result from future
                    result, formatted_output = future.result()

                    # Thread-safe result storage
                    with results_lock:
                        results[ip_str] = result
                        output_files.append(str(self.file_manager.get_output_path(ip)))

                    # Thread-safe counter update
                    with counter_lock:
                        successful += 1

                    logger.info(f"Successfully processed {ip_str} (parallel)")

                except Exception as e:
                    # Track failure
                    error_msg = f"Failed to process {ip_str}: {e}"
                    logger.error(error_msg)

                    # Thread-safe error storage
                    with results_lock:
                        errors[ip_str] = str(e)

                    # Thread-safe counter update
                    with counter_lock:
                        failed += 1

        return successful, failed, results, errors, output_files

    def _process_single_ip(
            self,
            ip: Union[IPv4Address,
                      IPv6Address],
            ip_str: str) -> tuple:
        """
        Process a single IP address (sequential mode).

        Args:
            ip: IP address object
            ip_str: IP address as string

        Returns:
            Tuple of (result, formatted_output)

        Raises:
            Exception: If processing fails
        """
        # Stage 1: Classification
        self.progress_tracker.start_stage(ip_str, "Classification")
        # Analyze IP (classification happens inside)
        result = self.analyzer.analyze(ip_str)
        self.progress_tracker.complete_stage(ip_str, "Classification")

        # Stage 2-4: Analysis modules (handled inside analyzer)
        # We'll mark them as complete after analysis
        self.progress_tracker.complete_stage(ip_str, "Local Info")
        self.progress_tracker.complete_stage(ip_str, "Internet Info")
        self.progress_tracker.complete_stage(ip_str, "Application Info")

        # Stage 5: Formatting
        self.progress_tracker.start_stage(ip_str, "Formatting")
        formatter = self._get_formatter()
        formatted_output = formatter.format_result(result)
        self.progress_tracker.complete_stage(ip_str, "Formatting")

        # Stage 6: Writing
        self.progress_tracker.start_stage(ip_str, "Writing")
        self.file_manager.write_result(ip, formatted_output)
        self.progress_tracker.complete_stage(ip_str, "Writing")

        return result, formatted_output

    def _process_single_ip_parallel(
            self,
            ip: Union[IPv4Address,
                      IPv6Address],
            idx: int,
            total_ips: int) -> tuple:
        """
        Process a single IP address (parallel mode).

        This method is called from worker threads and handles progress
        updates in a thread-safe manner.

        Args:
            ip: IP address object
            idx: IP index (1-based)
            total_ips: Total number of IPs being processed

        Returns:
            Tuple of (result, formatted_output)

        Raises:
            Exception: If processing fails
        """
        ip_str = str(ip)

        # Update overall progress (thread-safe)
        self.progress_tracker.update_overall_progress(idx, ip_str)

        logger.info(f"Processing IP {idx}/{total_ips}: {ip_str} (parallel)")

        # Stage 1: Classification
        self.progress_tracker.start_stage(ip_str, "Classification")
        result = self.analyzer.analyze(ip_str)
        self.progress_tracker.complete_stage(ip_str, "Classification")

        # Stage 2-4: Analysis modules (handled inside analyzer)
        self.progress_tracker.complete_stage(ip_str, "Local Info")
        self.progress_tracker.complete_stage(ip_str, "Internet Info")
        self.progress_tracker.complete_stage(ip_str, "Application Info")

        # Stage 5: Formatting
        self.progress_tracker.start_stage(ip_str, "Formatting")
        formatter = self._get_formatter()
        formatted_output = formatter.format_result(result)
        self.progress_tracker.complete_stage(ip_str, "Formatting")

        # Stage 6: Writing (thread-safe via FileOutputManager)
        self.progress_tracker.start_stage(ip_str, "Writing")
        self.file_manager.write_result(ip, formatted_output)
        self.progress_tracker.complete_stage(ip_str, "Writing")

        return result, formatted_output

    def _get_formatter(self):
        """
        Get appropriate formatter based on format type.

        Returns:
            Formatter instance
        """
        from .formatters.json import JSONFormatter
        from .formatters.html import HTMLFormatter

        reporting_mode = self.analyzer.config.reporting_mode

        if self.format_type == "json":
            return JSONFormatter(reporting_mode)
        else:
            return HTMLFormatter(reporting_mode)

    def sanitize_filename(
            self,
            ip: Union[IPv4Address,
                      IPv6Address]) -> str:
        """
        Sanitize IP address for use as filename.

        This is a convenience method that delegates to FileOutputManager.

        Args:
            ip: IP address object

        Returns:
            Sanitized filename
        """
        return self.file_manager.generate_filename(ip)
