"""
Unit tests for ProgressTracker exception safety.

Tests that display operations handle exceptions gracefully without
interrupting batch processing.
"""

import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from src.ip_sentinel.batch import ProgressTracker


class TestExceptionSafety:
    """Test exception handling in display operations."""

    def test_display_progress_handles_write_exception(self):
        """Test that display_progress handles write exceptions gracefully."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        tracker.update_overall_progress(5, "192.168.1.5")

        # Mock stdout.write to raise an exception
        with patch('sys.stdout.write', side_effect=IOError("Write failed")):
            with patch('sys.stdout.isatty', return_value=True):
                with patch('src.ip_sentinel.batch.logger') as mock_logger:
                    # Should not raise exception
                    tracker.display_progress()
                    
                    # Should log warning
                    mock_logger.warning.assert_called_once()
                    assert "Failed to display progress" in str(mock_logger.warning.call_args)

    def test_display_progress_handles_flush_exception(self):
        """Test that display_progress handles flush exceptions gracefully."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        tracker.update_overall_progress(5, "192.168.1.5")

        # Mock stdout.flush to raise an exception
        with patch('sys.stdout.isatty', return_value=True):
            with patch('sys.stdout.write'):
                with patch('sys.stdout.flush', side_effect=IOError("Flush failed")):
                    with patch('src.ip_sentinel.batch.logger') as mock_logger:
                        # Should not raise exception
                        tracker.display_progress()
                        
                        # Should log warning about flush failure
                        warning_calls = [str(call) for call in mock_logger.warning.call_args_list]
                        assert any("Failed to flush stdout" in str(call) for call in warning_calls)

    def test_flush_called_in_finally_block(self):
        """Test that flush is called even if display operations fail."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        tracker.update_overall_progress(5, "192.168.1.5")

        mock_flush = MagicMock()
        
        # Mock stdout.write to raise an exception
        with patch('sys.stdout.write', side_effect=IOError("Write failed")):
            with patch('sys.stdout.isatty', return_value=True):
                with patch('sys.stdout.flush', mock_flush):
                    with patch('src.ip_sentinel.batch.logger'):
                        # Call display_progress
                        tracker.display_progress()
                        
                        # Flush should still be called despite write exception
                        mock_flush.assert_called_once()

    def test_display_progress_continues_after_exception(self):
        """Test that progress tracking continues after display exception."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        
        # First update with exception
        with patch('sys.stdout.write', side_effect=IOError("Write failed")):
            with patch('sys.stdout.isatty', return_value=True):
                with patch('src.ip_sentinel.batch.logger'):
                    tracker.update_overall_progress(5, "192.168.1.5")
        
        # Internal state should still be updated
        assert tracker.current_ip == 5
        assert tracker.current_ip_address == "192.168.1.5"
        
        # Second update should work normally
        with patch('sys.stdout.isatty', return_value=True):
            with patch('sys.stdout.write') as mock_write:
                with patch('sys.stdout.flush'):
                    tracker.update_overall_progress(6, "192.168.1.6")
                    
                    # Should have written output
                    assert mock_write.called

    def test_mark_completed_handles_display_exception(self):
        """Test that mark_completed handles display exceptions gracefully."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        tracker.update_overall_progress(5, "192.168.1.5")
        
        # Mock display to raise exception
        with patch('sys.stdout.write', side_effect=IOError("Write failed")):
            with patch('sys.stdout.isatty', return_value=True):
                with patch('src.ip_sentinel.batch.logger'):
                    # Should not raise exception
                    tracker.mark_completed()
        
        # Completion counter should still be updated
        assert tracker.completed_scans == 1

    def test_non_tty_mode_no_exception_handling_needed(self):
        """Test that non-TTY mode returns early without exception handling."""
        tracker = ProgressTracker(total_ips=10, parallel=False)
        
        # In non-TTY mode, should return early
        with patch('sys.stdout.isatty', return_value=False):
            with patch('sys.stdout.write', side_effect=IOError("Should not be called")):
                # Should not raise exception because it returns early
                tracker.display_progress()
        
        # _displayed should remain False
        assert not tracker._displayed

    def test_exception_in_progress_calculation(self):
        """Test handling of exceptions during progress calculation."""
        tracker = ProgressTracker(total_ips=0, parallel=False)  # Zero total to test division
        
        with patch('sys.stdout.isatty', return_value=True):
            with patch('src.ip_sentinel.batch.logger') as mock_logger:
                # Should handle division by zero gracefully
                tracker.display_progress()
                
                # Should not have logged any warnings (division by zero is handled)
                # The code uses conditional: (x / y) if y > 0 else 0
                assert not mock_logger.warning.called

    def test_parallel_mode_exception_safety(self):
        """Test exception safety in parallel mode with locks."""
        tracker = ProgressTracker(total_ips=10, parallel=True)
        
        # Mock display to raise exception
        with patch('sys.stdout.write', side_effect=IOError("Write failed")):
            with patch('sys.stdout.isatty', return_value=True):
                with patch('src.ip_sentinel.batch.logger'):
                    # Should not raise exception even with locks
                    tracker.update_overall_progress(5, "192.168.1.5")
                    tracker.mark_completed()
        
        # State should be updated correctly
        assert tracker.current_ip == 5
        assert tracker.completed_scans == 1
