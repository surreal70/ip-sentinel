"""
HTML output formatter.
"""

from typing import Dict

from .base import OutputFormatter


class HTMLFormatter(OutputFormatter):
    """Formatter for HTML output."""

    def format_result(self, result: Dict) -> str:
        """
        Format analysis result as HTML.

        Args:
            result: Analysis result dictionary

        Returns:
            HTML formatted string
        """
        # TODO: Implement HTML formatting with proper escaping
        return f"<html><body><h1>IP Analysis Results</h1><p>{result}</p></body></html>"
