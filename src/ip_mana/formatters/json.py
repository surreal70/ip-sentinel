"""
JSON output formatter.
"""

import json
from typing import Any, Dict

from .base import OutputFormatter


class JSONFormatter(OutputFormatter):
    """Formatter for JSON output."""

    def format_result(self, result: Any) -> str:
        """
        Format analysis result as JSON.

        Args:
            result: Analysis result object or dictionary

        Returns:
            JSON formatted string
        """
        data = self._prepare_result_data(result)
        filtered_data = self._filter_by_verbosity(data)
        
        # Serialize all objects for JSON output
        serialized_data = self._serialize_for_output(filtered_data)
        
        try:
            return json.dumps(serialized_data, indent=2, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError) as e:
            # Fallback for any serialization issues
            error_result = {
                "error": f"JSON serialization failed: {str(e)}",
                "raw_data": str(serialized_data)
            }
            return json.dumps(error_result, indent=2, ensure_ascii=False)
