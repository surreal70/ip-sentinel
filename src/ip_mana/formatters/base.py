"""
Base output formatter interface.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict
from dataclasses import asdict
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address


class VerbosityMode:
    """Constants for verbosity modes."""
    DENSE = "dense"
    FULL = "full"
    FULL_ERR = "full-err"


class OutputFormatter(ABC):
    """Abstract base class for output formatters."""

    def __init__(self, verbosity_mode: str = VerbosityMode.DENSE):
        """
        Initialize the formatter.

        Args:
            verbosity_mode: One of 'dense', 'full', 'full-err'
        """
        self.set_verbosity(verbosity_mode)

    @abstractmethod
    def format_result(self, result: Any) -> str:
        """
        Format analysis result for output.

        Args:
            result: Analysis result object or dictionary

        Returns:
            Formatted string representation
        """

    def set_verbosity(self, mode: str) -> None:
        """Set the verbosity mode for output formatting."""
        valid_modes = [VerbosityMode.DENSE, VerbosityMode.FULL, VerbosityMode.FULL_ERR]
        if mode not in valid_modes:
            raise ValueError(
                f"Invalid verbosity mode: {mode}. Must be one of {valid_modes}")
        self.verbosity_mode = mode

    def _prepare_result_data(self, result: Any) -> Dict:
        """
        Convert result object to dictionary format for processing.

        Args:
            result: Analysis result object or dictionary

        Returns:
            Dictionary representation of the result
        """
        if hasattr(result, '__dict__'):
            # Handle dataclass or object with attributes
            if hasattr(result, '__dataclass_fields__'):
                return asdict(result)
            else:
                return vars(result)
        elif isinstance(result, dict):
            return result
        else:
            # Fallback for other types
            return {"result": result}

    def _filter_by_verbosity(self, data: Dict) -> Dict:
        """
        Filter data based on verbosity mode.

        Args:
            data: Raw data dictionary

        Returns:
            Filtered data according to verbosity settings
        """
        if self.verbosity_mode == VerbosityMode.DENSE:
            return self._filter_dense_mode(data)
        elif self.verbosity_mode == VerbosityMode.FULL:
            return self._filter_full_mode(data)
        elif self.verbosity_mode == VerbosityMode.FULL_ERR:
            return self._filter_full_err_mode(data)
        else:
            return data

    def _filter_dense_mode(self, data: Dict) -> Dict:
        """Filter data for dense mode - only show collected information."""
        filtered = {}
        for key, value in data.items():
            if self._has_meaningful_data(value):
                filtered[key] = value
        return filtered

    def _filter_full_mode(self, data: Dict) -> Dict:
        """Filter data for full mode - show all tests, mark empty ones."""
        filtered = {}
        for key, value in data.items():
            if self._has_meaningful_data(value):
                filtered[key] = value
            else:
                filtered[key] = "no results"
        return filtered

    def _filter_full_err_mode(self, data: Dict) -> Dict:
        """Filter data for full-err mode - include all data and errors."""
        # In full-err mode, we include everything including errors
        return data

    def _has_meaningful_data(self, value: Any) -> bool:
        """
        Check if a value contains meaningful data.

        Args:
            value: Value to check

        Returns:
            True if value contains meaningful data, False otherwise
        """
        if value is None:
            return False
        if isinstance(value, (str, list, dict)) and len(value) == 0:
            return False
        if isinstance(value, dict) and all(not self._has_meaningful_data(v)
                                           for v in value.values()):
            return False
        if isinstance(value, list) and all(not self._has_meaningful_data(v)
                                           for v in value):
            return False
        return True

    def _serialize_for_output(self, obj: Any) -> Any:
        """
        Serialize objects for output formatting.

        Args:
            obj: Object to serialize

        Returns:
            Serializable representation
        """
        if isinstance(obj, (IPv4Address, IPv6Address)):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            if hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            else:
                return vars(obj)
        elif isinstance(obj, dict):
            return {k: self._serialize_for_output(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_for_output(item) for item in obj]
        else:
            return obj
