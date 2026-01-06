"""
Human-readable console output formatter.
"""

from typing import Any, Dict, List
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from .base import OutputFormatter, VerbosityMode


class HumanFormatter(OutputFormatter):
    """Formatter for human-readable console output."""

    def format_result(self, result: Any) -> str:
        """
        Format analysis result as human-readable text.

        Args:
            result: Analysis result object or dictionary

        Returns:
            Human-readable formatted string
        """
        data = self._prepare_result_data(result)
        filtered_data = self._filter_by_verbosity(data)
        
        output_lines = []
        
        # Header
        ip_addr = data.get('ip_address', 'Unknown IP')
        timestamp = data.get('scan_timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp_str = timestamp
        else:
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(timestamp, 'strftime') else str(timestamp)
        
        output_lines.append("=" * 60)
        output_lines.append(f"IP Intelligence Analysis Report")
        output_lines.append("=" * 60)
        output_lines.append(f"IP Address: {ip_addr}")
        output_lines.append(f"Scan Time:  {timestamp_str}")
        output_lines.append("")

        # Classifications
        if 'classifications' in filtered_data:
            classifications = filtered_data['classifications']
            if self._has_meaningful_data(classifications):
                output_lines.append("Classifications:")
                output_lines.append("-" * 15)
                if isinstance(classifications, list):
                    for classification in classifications:
                        output_lines.append(f"  • {classification}")
                else:
                    output_lines.append(f"  • {classifications}")
                output_lines.append("")
            elif self.verbosity_mode in [VerbosityMode.FULL, VerbosityMode.FULL_ERR]:
                output_lines.append("Classifications: no results")
                output_lines.append("")

        # Local Information
        if 'local_info' in filtered_data:
            local_info = filtered_data['local_info']
            if self._has_meaningful_data(local_info) or self.verbosity_mode != VerbosityMode.DENSE:
                output_lines.append("Local Network Information:")
                output_lines.append("-" * 25)
                if local_info == "no results":
                    output_lines.append("  no results")
                elif isinstance(local_info, dict):
                    for key, value in local_info.items():
                        formatted_key = key.replace('_', ' ').title()
                        output_lines.append(f"  {formatted_key}: {value}")
                else:
                    output_lines.append(f"  {local_info}")
                output_lines.append("")

        # Internet Information
        if 'internet_info' in filtered_data:
            internet_info = filtered_data['internet_info']
            if self._has_meaningful_data(internet_info) or self.verbosity_mode != VerbosityMode.DENSE:
                output_lines.append("Internet Information:")
                output_lines.append("-" * 20)
                if internet_info == "no results":
                    output_lines.append("  no results")
                elif isinstance(internet_info, dict):
                    for key, value in internet_info.items():
                        formatted_key = key.replace('_', ' ').title()
                        if isinstance(value, list) and value:
                            output_lines.append(f"  {formatted_key}:")
                            for item in value:
                                output_lines.append(f"    • {item}")
                        else:
                            output_lines.append(f"  {formatted_key}: {value}")
                else:
                    output_lines.append(f"  {internet_info}")
                output_lines.append("")

        # Application Information
        if 'application_info' in filtered_data:
            app_info = filtered_data['application_info']
            if self._has_meaningful_data(app_info) or self.verbosity_mode != VerbosityMode.DENSE:
                output_lines.append("Application Information:")
                output_lines.append("-" * 23)
                if app_info == "no results" or not app_info:
                    output_lines.append("  no results")
                elif isinstance(app_info, dict):
                    for app_name, app_data in app_info.items():
                        output_lines.append(f"  {app_name}:")
                        if isinstance(app_data, dict):
                            for key, value in app_data.items():
                                formatted_key = key.replace('_', ' ').title()
                                output_lines.append(f"    {formatted_key}: {value}")
                        else:
                            output_lines.append(f"    {app_data}")
                else:
                    output_lines.append(f"  {app_info}")
                output_lines.append("")

        # Errors (only in full-err mode or if there are errors in other modes)
        if 'errors' in filtered_data:
            errors = filtered_data['errors']
            if (self.verbosity_mode == VerbosityMode.FULL_ERR or 
                (self._has_meaningful_data(errors) and self.verbosity_mode != VerbosityMode.DENSE)):
                output_lines.append("Errors and Issues:")
                output_lines.append("-" * 17)
                if not self._has_meaningful_data(errors):
                    output_lines.append("  no errors")
                elif isinstance(errors, list):
                    for error in errors:
                        output_lines.append(f"  ⚠ {error}")
                else:
                    output_lines.append(f"  ⚠ {errors}")
                output_lines.append("")

        # Footer
        output_lines.append("=" * 60)
        
        return "\n".join(output_lines)
