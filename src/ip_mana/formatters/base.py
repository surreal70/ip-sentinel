"""
Base output formatter interface.
"""

from abc import ABC, abstractmethod
from typing import Dict


class OutputFormatter(ABC):
    """Abstract base class for output formatters."""

    def __init__(self, verbosity_mode: str = "dense"):
        """
        Initialize the formatter.

        Args:
            verbosity_mode: One of 'dense', 'full', 'full-err'
        """
        self.verbosity_mode = verbosity_mode

    @abstractmethod
    def format_result(self, result: Dict) -> str:
        """
        Format analysis result for output.

        Args:
            result: Analysis result dictionary

        Returns:
            Formatted string representation
        """
        pass

    def set_verbosity(self, mode: str) -> None:
        """Set the verbosity mode for output formatting."""
        if mode not in ["dense", "full", "full-err"]:
            raise ValueError(f"Invalid verbosity mode: {mode}")
        self.verbosity_mode = mode
