"""
HTML output formatter.
"""

import html
from typing import Any, Dict, List
from datetime import datetime

from .base import OutputFormatter, VerbosityMode


class HTMLFormatter(OutputFormatter):
    """Formatter for HTML output."""

    def format_result(self, result: Any) -> str:
        """
        Format analysis result as HTML.

        Args:
            result: Analysis result object or dictionary

        Returns:
            HTML formatted string with proper escaping
        """
        data = self._prepare_result_data(result)
        filtered_data = self._filter_by_verbosity(data)

        # Build HTML document
        html_parts = []

        # HTML header with CSS styling
        html_parts.append(self._get_html_header())

        # Main content
        html_parts.append('<div class="container">')

        # Title and header info
        ip_addr = html.escape(str(data.get('ip_address', 'Unknown IP')))
        timestamp = data.get('scan_timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp_str = html.escape(timestamp)
        else:
            timestamp_str = html.escape(timestamp.strftime(
                '%Y-%m-%d %H:%M:%S') if hasattr(timestamp, 'strftime') else str(timestamp))

        html_parts.append('<header>')
        html_parts.append('<h1>IP Intelligence Analysis Report</h1>')
        html_parts.append('<div class="ip-info">')
        html_parts.append(f'<span class="ip-address">IP Address: {ip_addr}</span>')
        html_parts.append(f'<span class="scan-time">Scan Time: {timestamp_str}</span>')
        html_parts.append('</div>')
        html_parts.append('</header>')

        html_parts.append('<main>')

        # Classifications section
        if 'classifications' in filtered_data:
            html_parts.append(
                self._format_section(
                    'Classifications',
                    filtered_data['classifications']))

        # Local Information section
        if 'local_info' in filtered_data:
            html_parts.append(
                self._format_section(
                    'Local Network Information',
                    filtered_data['local_info']))

        # Internet Information section
        if 'internet_info' in filtered_data:
            html_parts.append(
                self._format_section(
                    'Internet Information',
                    filtered_data['internet_info']))

        # Application Information section
        if 'application_info' in filtered_data:
            html_parts.append(
                self._format_section(
                    'Application Information',
                    filtered_data['application_info']))

        # Errors section (only in appropriate verbosity modes)
        if 'errors' in filtered_data:
            errors = filtered_data['errors']
            if (self.verbosity_mode == VerbosityMode.FULL_ERR or (
                    self._has_meaningful_data(errors) and self.verbosity_mode != VerbosityMode.DENSE)):
                html_parts.append(
                    self._format_section(
                        'Errors and Issues',
                        errors,
                        section_class='errors'))

        html_parts.append('</main>')
        html_parts.append('</div>')

        # HTML footer
        html_parts.append(self._get_html_footer())

        return '\n'.join(html_parts)

    def _get_html_header(self) -> str:
        """Generate HTML document header with CSS styling."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Intelligence Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        header {
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        h1 {
            color: #007acc;
            margin: 0 0 15px 0;
            font-size: 2.2em;
        }
        .ip-info {
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
        }
        .ip-address, .scan-time {
            font-weight: bold;
            color: #555;
        }
        .section {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 6px;
            overflow: hidden;
        }
        .section-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #ddd;
            font-weight: bold;
            font-size: 1.1em;
            color: #495057;
        }
        .section-content {
            padding: 20px;
        }
        .errors .section-header {
            background: #f8d7da;
            color: #721c24;
        }
        .no-results {
            color: #6c757d;
            font-style: italic;
        }
        .key-value {
            margin-bottom: 10px;
        }
        .key {
            font-weight: bold;
            color: #495057;
            display: inline-block;
            min-width: 150px;
        }
        .value {
            color: #212529;
        }
        ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        li {
            margin-bottom: 5px;
        }
        .nested-section {
            margin: 15px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 4px;
            border-left: 4px solid #007acc;
        }
        .nested-title {
            font-weight: bold;
            color: #007acc;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>'''

    def _get_html_footer(self) -> str:
        """Generate HTML document footer."""
        return '''</body>
</html>'''

    def _format_section(self, title: str, data: Any, section_class: str = '') -> str:
        """Format a data section as HTML."""
        escaped_title = html.escape(title)
        class_attr = f' class="section {section_class}"' if section_class else ' class="section"'

        html_parts = [f'<div{class_attr}>']
        html_parts.append(f'<div class="section-header">{escaped_title}</div>')
        html_parts.append('<div class="section-content">')

        if data == "no results" or not self._has_meaningful_data(data):
            html_parts.append('<div class="no-results">no results</div>')
        else:
            html_parts.append(self._format_data_as_html(data))

        html_parts.append('</div>')
        html_parts.append('</div>')

        return '\n'.join(html_parts)

    def _format_data_as_html(self, data: Any) -> str:
        """Format data content as HTML."""
        if isinstance(data, dict):
            return self._format_dict_as_html(data)
        elif isinstance(data, list):
            return self._format_list_as_html(data)
        else:
            return f'<div class="value">{html.escape(str(data))}</div>'

    def _format_dict_as_html(self, data: Dict) -> str:
        """Format dictionary data as HTML."""
        html_parts = []

        for key, value in data.items():
            formatted_key = html.escape(key.replace('_', ' ').title())

            if isinstance(value, dict):
                html_parts.append('<div class="nested-section">')
                html_parts.append(f'<div class="nested-title">{formatted_key}</div>')
                html_parts.append(self._format_dict_as_html(value))
                html_parts.append('</div>')
            elif isinstance(value, list):
                html_parts.append('<div class="key-value">')
                html_parts.append(f'<span class="key">{formatted_key}:</span>')
                html_parts.append(self._format_list_as_html(value))
                html_parts.append('</div>')
            else:
                escaped_value = html.escape(str(value))
                html_parts.append('<div class="key-value">')
                html_parts.append(f'<span class="key">{formatted_key}:</span>')
                html_parts.append(f'<span class="value">{escaped_value}</span>')
                html_parts.append('</div>')

        return '\n'.join(html_parts)

    def _format_list_as_html(self, data: List) -> str:
        """Format list data as HTML."""
        if not data:
            return '<div class="no-results">no items</div>'

        html_parts = ['<ul>']
        for item in data:
            if isinstance(item, dict):
                html_parts.append('<li>')
                html_parts.append(self._format_dict_as_html(item))
                html_parts.append('</li>')
            else:
                escaped_item = html.escape(str(item))
                html_parts.append(f'<li>{escaped_item}</li>')
        html_parts.append('</ul>')

        return '\n'.join(html_parts)
