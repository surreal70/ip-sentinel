"""
JSON output formatter.
"""

import json
from typing import Dict

from .base import OutputFormatter


class JSONFormatter(OutputFormatter):
    """Formatter for JSON output."""

    def format_result(self, result: Dict) -> str:
        """
        Format analysis result as JSON.

        Args:
            result: Analysis result dictionary

        Returns:
            JSON formatted string
        """
        # TODO: Implement JSON formatting with proper serialization
        return json.dumps(result, indent=2, default=str)
