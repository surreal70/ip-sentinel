"""
Human-readable console output formatter.
"""

from typing import Dict

from .base import OutputFormatter


class HumanFormatter(OutputFormatter):
    """Formatter for human-readable console output."""

    def format_result(self, result: Dict) -> str:
        """
        Format analysis result as human-readable text.

        Args:
            result: Analysis result dictionary

        Returns:
            Human-readable formatted string
        """
        # TODO: Implement human-readable formatting
        return f"Analysis results for {result.get('ip_address', 'unknown IP')}"
