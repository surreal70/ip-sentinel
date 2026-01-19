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
        .traceroute-tree {
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .traceroute-method {
            font-weight: bold;
            color: #007acc;
            margin-bottom: 10px;
        }
        .traceroute-hop {
            margin-left: 20px;
            padding: 5px 0;
            color: #495057;
        }
        .traceroute-hop.destination {
            color: #28a745;
            font-weight: bold;
        }
        .traceroute-hop.failed {
            color: #dc3545;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            background: white;
        }
        table th {
            background: #007acc;
            color: white;
            padding: 10px;
            text-align: left;
            font-weight: bold;
        }
        table td {
            padding: 8px 10px;
            border-bottom: 1px solid #ddd;
        }
        table tr:hover {
            background: #f8f9fa;
        }
        table tr:last-child td {
            border-bottom: none;
        }
        .port-number {
            font-weight: bold;
            color: #007acc;
        }
        .service-name {
            color: #495057;
        }
        .state-open {
            color: #28a745;
            font-weight: bold;
        }
        .state-closed {
            color: #dc3545;
        }
        .state-filtered {
            color: #ffc107;
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
            # Special handling for application info section
            if title == 'Application Information' and isinstance(data, dict):
                html_parts.append(self._format_application_info_html(data))
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
            # Convert key to string if it's not already
            key_str = str(key) if not isinstance(key, str) else key
            formatted_key = html.escape(key_str.replace('_', ' ').title())

            # Special handling for nmap results
            if key == 'nmap_results' and isinstance(value, dict):
                html_parts.append(self._format_nmap_results_html(value))
            # Special handling for SSL results
            elif key == 'ssl_results' and isinstance(value, list):
                html_parts.append(self._format_ssl_results_html(value))
            # Special handling for traceroute results
            elif key == 'traceroute_results' and isinstance(value, list):
                html_parts.append(self._format_traceroute_tree_html(value))
            elif isinstance(value, dict):
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

    def _format_nmap_results_html(self, nmap_data: dict) -> str:
        """
        Format nmap results as compact HTML tables.

        Args:
            nmap_data: Nmap results dictionary

        Returns:
            HTML string with table formatting
        """
        html_parts = ['<div class="key-value">']
        html_parts.append('<span class="key">Nmap Results:</span>')
        html_parts.append('<div style="margin-top: 10px;">')

        # Host status
        host_up = nmap_data.get('host_up', False)
        status_class = 'state-open' if host_up else 'state-closed'
        status_text = '✓ Up' if host_up else '✗ Down'
        html_parts.append('<div class="key-value">')
        html_parts.append('<span class="key">Host Status:</span>')
        html_parts.append(f'<span class="value {status_class}">{html.escape(status_text)}</span>')
        html_parts.append('</div>')

        # OS detection
        os_detection = nmap_data.get('os_detection', {})
        if os_detection:
            html_parts.append('<div class="key-value">')
            html_parts.append('<span class="key">OS Detection:</span>')
            
            if 'note' in os_detection:
                html_parts.append(f'<span class="value" style="font-style: italic; color: #6c757d;">{html.escape(os_detection["note"])}</span>')
            elif 'matches' in os_detection and os_detection['matches']:
                html_parts.append('<table>')
                html_parts.append('<thead><tr>')
                html_parts.append('<th>Operating System</th>')
                html_parts.append('<th>Accuracy</th>')
                html_parts.append('</tr></thead>')
                html_parts.append('<tbody>')
                
                for match in os_detection['matches'][:3]:  # Show top 3 matches
                    name = html.escape(match.get('name', 'Unknown'))
                    accuracy = match.get('accuracy', 0)
                    html_parts.append('<tr>')
                    html_parts.append(f'<td>{name}</td>')
                    html_parts.append(f'<td>{accuracy}%</td>')
                    html_parts.append('</tr>')
                
                html_parts.append('</tbody></table>')
            
            html_parts.append('</div>')

        # Open ports table
        open_ports = nmap_data.get('open_ports', [])
        if open_ports:
            html_parts.append('<div class="key-value">')
            html_parts.append(f'<span class="key">Open Ports:</span> <span class="value">{len(open_ports)} found</span>')
            html_parts.append('<table>')
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Port</th>')
            html_parts.append('<th>Protocol</th>')
            html_parts.append('<th>State</th>')
            html_parts.append('<th>Service</th>')
            html_parts.append('<th>Version</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for port_info in open_ports:
                port = html.escape(str(port_info.get('port', '?')))
                protocol = html.escape(port_info.get('protocol', 'tcp'))
                state = port_info.get('state', 'unknown')
                service = html.escape(port_info.get('service', 'unknown'))
                version = html.escape(port_info.get('version', ''))
                
                state_class = f'state-{state}' if state in ['open', 'closed', 'filtered'] else ''
                
                html_parts.append('<tr>')
                html_parts.append(f'<td class="port-number">{port}</td>')
                html_parts.append(f'<td>{protocol}</td>')
                html_parts.append(f'<td class="{state_class}">{html.escape(state)}</td>')
                html_parts.append(f'<td class="service-name">{service}</td>')
                html_parts.append(f'<td>{version if version else "-"}</td>')
                html_parts.append('</tr>')
            
            html_parts.append('</tbody></table>')
            html_parts.append('</div>')

        html_parts.append('</div>')
        html_parts.append('</div>')

        return '\n'.join(html_parts)

    def _format_ssl_results_html(self, ssl_results: list) -> str:
        """
        Format SSL/TLS results with certificate deduplication in HTML.

        Args:
            ssl_results: List of SSL result dictionaries

        Returns:
            HTML string with deduplicated certificate information
        """
        if not ssl_results:
            return '<div class="no-results">no SSL results</div>'

        html_parts = ['<div class="key-value">']
        html_parts.append('<span class="key">SSL/TLS Results:</span>')
        html_parts.append('<div style="margin-top: 10px;">')

        # Group certificates by their content to deduplicate
        cert_groups = {}
        port_specific_data = {}  # Track port-specific cipher suites and vulnerabilities
        
        for ssl_result in ssl_results:
            port = ssl_result.get('port', 'Unknown')
            certificate = ssl_result.get('certificate')
            cipher_suites = ssl_result.get('cipher_suites', [])
            vulnerabilities = ssl_result.get('vulnerabilities', [])
            
            # Store port-specific data
            port_specific_data[port] = {
                'cipher_suites': cipher_suites,
                'vulnerabilities': vulnerabilities
            }
            
            if certificate and isinstance(certificate, dict):
                # Check if this is a reference to another port
                if 'reference_to_port' in certificate:
                    # Track this port but link it to the primary certificate
                    ref_port = certificate.get('reference_to_port')
                    # We'll handle this when displaying the primary certificate
                    continue
                
                # Create a key based on certificate content
                cert_key = (
                    certificate.get('subject', ''),
                    certificate.get('issuer', ''),
                    certificate.get('not_valid_before', ''),
                    certificate.get('not_valid_after', '')
                )
                
                if cert_key not in cert_groups:
                    cert_groups[cert_key] = {
                        'certificate': certificate,
                        'ports': [],
                        'cipher_suites': cipher_suites,
                        'vulnerabilities': vulnerabilities
                    }
                
                cert_groups[cert_key]['ports'].append(port)

        # Display each unique certificate with its ports
        for cert_info in cert_groups.values():
            certificate = cert_info['certificate']
            ports = cert_info['ports']
            
            # Check if certificate has shared_across_ports info from deduplication
            shared_ports = certificate.get('shared_across_ports', ports)
            cipher_suites = cert_info['cipher_suites']
            vulnerabilities = cert_info['vulnerabilities']
            
            # Certificate header with ports
            ports_str = ', '.join(map(str, sorted(shared_ports)))
            html_parts.append('<div class="nested-section">')
            html_parts.append(f'<div class="nested-title">Certificate (Ports: {html.escape(ports_str)})</div>')
            
            # Certificate details table
            html_parts.append('<table>')
            html_parts.append('<tbody>')
            
            # Subject
            subject = certificate.get('subject', 'Unknown')
            if isinstance(subject, str) and subject.startswith('<Name(') and subject.endswith(')>'):
                subject = subject[6:-2]
            html_parts.append('<tr>')
            html_parts.append('<td style="font-weight: bold; width: 150px;">Subject</td>')
            html_parts.append(f'<td style="color: #28a745;">{html.escape(str(subject))}</td>')
            html_parts.append('</tr>')
            
            # Issuer
            issuer = certificate.get('issuer', 'Unknown')
            if isinstance(issuer, str) and issuer.startswith('<Name(') and issuer.endswith(')>'):
                issuer = issuer[6:-2]
            html_parts.append('<tr>')
            html_parts.append('<td style="font-weight: bold;">Issuer</td>')
            html_parts.append(f'<td>{html.escape(str(issuer))}</td>')
            html_parts.append('</tr>')
            
            # Valid from
            not_valid_before = certificate.get('not_valid_before', 'Unknown')
            html_parts.append('<tr>')
            html_parts.append('<td style="font-weight: bold;">Valid From</td>')
            html_parts.append(f'<td>{html.escape(str(not_valid_before))}</td>')
            html_parts.append('</tr>')
            
            # Valid until
            not_valid_after = certificate.get('not_valid_after', 'Unknown')
            html_parts.append('<tr>')
            html_parts.append('<td style="font-weight: bold;">Valid Until</td>')
            html_parts.append(f'<td>{html.escape(str(not_valid_after))}</td>')
            html_parts.append('</tr>')
            
            html_parts.append('</tbody></table>')
            
            # If certificate is shared across multiple ports, show per-port details
            if len(shared_ports) > 1:
                html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                html_parts.append('<span class="key">Port-Specific Details:</span>')
                html_parts.append('</div>')
                
                for port in sorted(shared_ports):
                    port_data = port_specific_data.get(port, {})
                    port_cipher_suites = port_data.get('cipher_suites', [])
                    port_vulnerabilities = port_data.get('vulnerabilities', [])
                    
                    html_parts.append('<div style="margin-left: 20px; margin-top: 10px; padding: 10px; background: #f8f9fa; border-left: 3px solid #007acc;">')
                    html_parts.append(f'<div style="font-weight: bold; color: #007acc; margin-bottom: 5px;">Port {port}</div>')
                    
                    # Cipher suites for this port
                    if port_cipher_suites:
                        html_parts.append('<div class="key-value">')
                        html_parts.append(f'<span class="key">Cipher Suites:</span> <span class="value">{len(port_cipher_suites)} supported</span>')
                        html_parts.append('<ul style="margin-top: 5px; margin-bottom: 5px;">')
                        # Show ALL cipher suites for each port
                        for cipher in port_cipher_suites:
                            html_parts.append(f'<li style="color: #007acc; font-size: 0.9em;">{html.escape(cipher)}</li>')
                        html_parts.append('</ul>')
                        html_parts.append('</div>')
                    
                    # Vulnerabilities for this port
                    if port_vulnerabilities:
                        html_parts.append('<div class="key-value">')
                        html_parts.append(f'<span class="key" style="color: #dc3545;">Vulnerabilities:</span> <span class="value" style="color: #dc3545; font-weight: bold;">{len(port_vulnerabilities)} found</span>')
                        html_parts.append('<ul style="margin-top: 5px; margin-bottom: 5px;">')
                        for vuln in port_vulnerabilities:
                            html_parts.append(f'<li style="color: #dc3545; font-size: 0.9em;">{html.escape(vuln)}</li>')
                        html_parts.append('</ul>')
                        html_parts.append('</div>')
                    else:
                        html_parts.append('<div class="key-value">')
                        html_parts.append('<span class="key">Vulnerabilities:</span> <span class="value" style="color: #28a745;">✓ None detected</span>')
                        html_parts.append('</div>')
                    
                    html_parts.append('</div>')
            else:
                # Single port - show cipher suites and vulnerabilities directly
                # Cipher suites - show ALL of them
                if cipher_suites:
                    html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                    html_parts.append(f'<span class="key">Cipher Suites:</span> <span class="value">{len(cipher_suites)} supported</span>')
                    html_parts.append('<ul style="margin-top: 5px;">')
                    # Show ALL cipher suites instead of limiting to 5
                    for cipher in cipher_suites:
                        html_parts.append(f'<li style="color: #007acc;">{html.escape(cipher)}</li>')
                    html_parts.append('</ul>')
                    html_parts.append('</div>')
                
                # Vulnerabilities
                if vulnerabilities:
                    html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                    html_parts.append(f'<span class="key" style="color: #dc3545;">Vulnerabilities:</span> <span class="value" style="color: #dc3545; font-weight: bold;">{len(vulnerabilities)} found</span>')
                    html_parts.append('<ul style="margin-top: 5px;">')
                    for vuln in vulnerabilities:
                        html_parts.append(f'<li style="color: #dc3545;">{html.escape(vuln)}</li>')
                    html_parts.append('</ul>')
                    html_parts.append('</div>')
                else:
                    html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                    html_parts.append('<span class="key">Vulnerabilities:</span> <span class="value" style="color: #28a745;">✓ None detected</span>')
                    html_parts.append('</div>')
            
            html_parts.append('</div>')  # Close nested-section

        html_parts.append('</div>')
        html_parts.append('</div>')

        return '\n'.join(html_parts)

    def _format_application_info_html(self, app_info: dict) -> str:
        """
        Format application module information (NetBox, CheckMK, OpenVAS) in compact HTML.

        Args:
            app_info: Dictionary containing application module results

        Returns:
            HTML string with compact table formatting
        """
        if not app_info:
            return '<div class="no-results">no application information</div>'

        html_parts = []

        for app_name, app_data in app_info.items():
            html_parts.append('<div class="nested-section">')
            html_parts.append(f'<div class="nested-title">{html.escape(app_name.upper())}</div>')
            
            if not isinstance(app_data, dict):
                html_parts.append(f'<div class="value">{html.escape(str(app_data))}</div>')
                html_parts.append('</div>')
                continue
            
            # Extract standard fields
            success = app_data.get('success', False)
            error_message = app_data.get('error_message')
            source = app_data.get('source', 'Unknown')
            data = app_data.get('data')
            
            # Status and source in a compact table
            html_parts.append('<table>')
            html_parts.append('<tbody>')
            
            # Status row
            status_class = 'state-open' if success else 'state-closed'
            status_text = '✓ Success' if success else '✗ Failed'
            html_parts.append('<tr>')
            html_parts.append('<td style="font-weight: bold; width: 150px;">Status</td>')
            html_parts.append(f'<td class="{status_class}">{html.escape(status_text)}</td>')
            html_parts.append('</tr>')
            
            # Source row
            html_parts.append('<tr>')
            html_parts.append('<td style="font-weight: bold;">Source</td>')
            html_parts.append(f'<td style="color: #007acc;">{html.escape(source)}</td>')
            html_parts.append('</tr>')
            
            # Error message if present
            if error_message:
                html_parts.append('<tr>')
                html_parts.append('<td style="font-weight: bold;">Error</td>')
                html_parts.append(f'<td style="color: #dc3545;">{html.escape(error_message)}</td>')
                html_parts.append('</tr>')
            
            html_parts.append('</tbody></table>')
            
            # Data section - format based on structure
            if data and isinstance(data, dict):
                # Count items in each category
                summary_items = []
                for key, value in data.items():
                    if isinstance(value, list):
                        count = len(value)
                        if count > 0:
                            summary_items.append(f"{count} {key.replace('_', ' ')}")
                
                if summary_items:
                    summary = ", ".join(summary_items)
                    html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                    html_parts.append(f'<span class="key">Found:</span> <span class="value" style="color: #28a745;">{html.escape(summary)}</span>')
                    html_parts.append('</div>')
                    
                    # Show details for each category in compact tables
                    for key, value in data.items():
                        if isinstance(value, list) and value:
                            formatted_key = key.replace('_', ' ').title()
                            
                            html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                            html_parts.append(f'<span class="key">{html.escape(formatted_key)}:</span> <span class="value">{len(value)} items</span>')
                            
                            # Format based on category
                            if key in ['prefixes', 'ip_addresses', 'devices', 'interfaces', 
                                      'virtual_machines', 'clusters', 'sites', 'tenants', 
                                      'vlans', 'vrfs', 'aggregates', 'ip_ranges', 'contacts']:
                                # NetBox items - show in compact table
                                html_parts.append(self._format_netbox_items_table(value, key))
                            elif key == 'services':
                                # Could be CheckMK or NetBox services - check structure
                                if value and isinstance(value[0], dict) and 'extensions' in value[0]:
                                    # CheckMK services
                                    html_parts.append(self._format_checkmk_services_table(value))
                                else:
                                    # NetBox services
                                    html_parts.append(self._format_netbox_items_table(value, key))
                            elif key == 'hosts':
                                # CheckMK hosts - show in compact table
                                html_parts.append(self._format_checkmk_hosts_table(value))
                            else:
                                # Generic list formatting
                                html_parts.append('<ul style="margin-top: 5px;">')
                                for i, item in enumerate(value[:5]):  # Show first 5
                                    if isinstance(item, dict):
                                        # Extract key identifying information
                                        display_info = self._extract_display_info_html(item, key)
                                        if display_info:
                                            html_parts.append(f'<li>{display_info}</li>')
                                    else:
                                        html_parts.append(f'<li>{html.escape(str(item))}</li>')
                                
                                if len(value) > 5:
                                    remaining = len(value) - 5
                                    html_parts.append(f'<li style="font-style: italic; color: #6c757d;">... and {remaining} more</li>')
                                html_parts.append('</ul>')
                            
                            html_parts.append('</div>')
                else:
                    html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                    html_parts.append('<span class="key">Data:</span> <span class="value" style="font-style: italic; color: #6c757d;">No items found</span>')
                    html_parts.append('</div>')
            elif data:
                html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                html_parts.append('<span class="key">Data:</span> <span class="value" style="font-style: italic; color: #6c757d;">Available (see JSON output for details)</span>')
                html_parts.append('</div>')
            else:
                html_parts.append('<div class="key-value" style="margin-top: 10px;">')
                html_parts.append('<span class="key">Data:</span> <span class="value" style="font-style: italic; color: #6c757d;">None</span>')
                html_parts.append('</div>')
            
            html_parts.append('</div>')  # Close nested-section

        return '\n'.join(html_parts)

    def _format_netbox_items_table(self, items: list, category: str) -> str:
        """Format NetBox items in a compact table with clickable links."""
        if not items:
            return ''
        
        html_parts = ['<table style="margin-top: 5px;">']
        
        # Determine columns based on category
        if category == 'prefixes':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Prefix</th>')
            html_parts.append('<th>Status</th>')
            html_parts.append('<th>VRF</th>')
            html_parts.append('<th>Description</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:  # Show first 10
                prefix = html.escape(str(item.get('prefix', '-')))
                status = html.escape(str(item.get('status', {}).get('label', '-')))
                vrf = html.escape(str(item.get('vrf', {}).get('name', '-') if item.get('vrf') else '-'))
                description = html.escape(str(item.get('description', '-')))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                # Make prefix clickable if URL is available
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{prefix}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{prefix}</td>')
                html_parts.append(f'<td>{status}</td>')
                html_parts.append(f'<td>{vrf}</td>')
                html_parts.append(f'<td>{description}</td>')
                html_parts.append('</tr>')
        
        elif category == 'devices':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Device</th>')
            html_parts.append('<th>Role</th>')
            html_parts.append('<th>Site</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                role = html.escape(str(item.get('device_role', {}).get('name', '-') if item.get('device_role') else '-'))
                site = html.escape(str(item.get('site', {}).get('name', '-') if item.get('site') else '-'))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                # Make device name clickable if URL is available
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{name}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{name}</td>')
                html_parts.append(f'<td>{role}</td>')
                html_parts.append(f'<td>{site}</td>')
                html_parts.append('</tr>')
        
        elif category == 'interfaces':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Interface</th>')
            html_parts.append('<th>Device</th>')
            html_parts.append('<th>Type</th>')
            html_parts.append('<th>Enabled</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                device = html.escape(str(item.get('device', {}).get('name', '-') if item.get('device') else '-'))
                iface_type = html.escape(str(item.get('type', {}).get('label', '-') if item.get('type') else '-'))
                enabled = '✓' if item.get('enabled') else '✗'
                enabled_class = 'state-open' if item.get('enabled') else 'state-closed'
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                # Make interface name clickable if URL is available
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{name}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{name}</td>')
                html_parts.append(f'<td>{device}</td>')
                html_parts.append(f'<td>{iface_type}</td>')
                html_parts.append(f'<td class="{enabled_class}">{enabled}</td>')
                html_parts.append('</tr>')
        
        elif category == 'virtual_machines':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>VM Name</th>')
            html_parts.append('<th>Status</th>')
            html_parts.append('<th>Cluster</th>')
            html_parts.append('<th>vCPUs</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                status = html.escape(str(item.get('status', {}).get('label', '-') if item.get('status') else '-'))
                cluster = html.escape(str(item.get('cluster', {}).get('name', '-') if item.get('cluster') else '-'))
                vcpus = html.escape(str(item.get('vcpus', '-')))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{name}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{name}</td>')
                html_parts.append(f'<td>{status}</td>')
                html_parts.append(f'<td>{cluster}</td>')
                html_parts.append(f'<td>{vcpus}</td>')
                html_parts.append('</tr>')
        
        elif category == 'clusters':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Cluster</th>')
            html_parts.append('<th>Type</th>')
            html_parts.append('<th>VM Count</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                cluster_type = html.escape(str(item.get('type', {}).get('name', '-') if item.get('type') else '-'))
                vm_count = html.escape(str(item.get('virtual_machine_count', 0)))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{name}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{name}</td>')
                html_parts.append(f'<td>{cluster_type}</td>')
                html_parts.append(f'<td>{vm_count}</td>')
                html_parts.append('</tr>')
        
        elif category == 'sites':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Site</th>')
            html_parts.append('<th>Status</th>')
            html_parts.append('<th>Region</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                status = html.escape(str(item.get('status', {}).get('label', '-') if item.get('status') else '-'))
                region = html.escape(str(item.get('region', {}).get('name', '-') if item.get('region') else '-'))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{name}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{name}</td>')
                html_parts.append(f'<td>{status}</td>')
                html_parts.append(f'<td>{region}</td>')
                html_parts.append('</tr>')
        
        elif category == 'tenants':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Tenant</th>')
            html_parts.append('<th>Devices</th>')
            html_parts.append('<th>VMs</th>')
            html_parts.append('<th>IP Addresses</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                device_count = html.escape(str(item.get('device_count', 0)))
                vm_count = html.escape(str(item.get('virtualmachine_count', 0)))
                ip_count = html.escape(str(item.get('ipaddress_count', 0)))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{name}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{name}</td>')
                html_parts.append(f'<td>{device_count}</td>')
                html_parts.append(f'<td>{vm_count}</td>')
                html_parts.append(f'<td>{ip_count}</td>')
                html_parts.append('</tr>')
        
        elif category == 'vlans':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>VLAN</th>')
            html_parts.append('<th>Name</th>')
            html_parts.append('<th>Status</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                vid = html.escape(str(item.get('vid', '-')))
                name = html.escape(str(item.get('name', '-')))
                status = html.escape(str(item.get('status', {}).get('label', '-') if item.get('status') else '-'))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{vid}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{vid}</td>')
                html_parts.append(f'<td>{name}</td>')
                html_parts.append(f'<td>{status}</td>')
                html_parts.append('</tr>')
        
        elif category == 'vrfs':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>VRF</th>')
            html_parts.append('<th>RD</th>')
            html_parts.append('<th>IP Count</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                rd = html.escape(str(item.get('rd', '-') if item.get('rd') else '-'))
                ip_count = html.escape(str(item.get('ipaddress_count', 0)))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{name}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{name}</td>')
                html_parts.append(f'<td>{rd}</td>')
                html_parts.append(f'<td>{ip_count}</td>')
                html_parts.append('</tr>')
        
        elif category == 'aggregates':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Prefix</th>')
            html_parts.append('<th>RIR</th>')
            html_parts.append('<th>Description</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                prefix = html.escape(str(item.get('prefix', '-')))
                rir = html.escape(str(item.get('rir', {}).get('name', '-') if item.get('rir') else '-'))
                description = html.escape(str(item.get('description', '-')))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{prefix}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{prefix}</td>')
                html_parts.append(f'<td>{rir}</td>')
                html_parts.append(f'<td>{description}</td>')
                html_parts.append('</tr>')
        
        elif category == 'ip_ranges':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Range</th>')
            html_parts.append('<th>Description</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                start = html.escape(str(item.get('start_address', '-')))
                end = html.escape(str(item.get('end_address', '-')))
                range_str = f"{start} - {end}"
                description = html.escape(str(item.get('description', '-')))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{range_str}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{range_str}</td>')
                html_parts.append(f'<td>{description}</td>')
                html_parts.append('</tr>')
        
        elif category == 'contacts':
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Name</th>')
            html_parts.append('<th>Email</th>')
            html_parts.append('<th>Phone</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                email = html.escape(str(item.get('email', '-')))
                phone = html.escape(str(item.get('phone', '-')))
                
                html_parts.append('<tr>')
                html_parts.append(f'<td>{name}</td>')
                html_parts.append(f'<td>{email}</td>')
                html_parts.append(f'<td>{phone}</td>')
                html_parts.append('</tr>')
        
        elif category == 'services':
            # NetBox services (not CheckMK)
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Service</th>')
            html_parts.append('<th>Protocol</th>')
            html_parts.append('<th>Ports</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                name = html.escape(str(item.get('name', '-')))
                protocol = html.escape(str(item.get('protocol', {}).get('label', '-') if item.get('protocol') else '-'))
                ports = ', '.join(map(str, item.get('ports', [])))
                web_url = item.get('web_url', '')
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{name}</a></td>')
                else:
                    html_parts.append(f'<td style="color: #007acc;">{name}</td>')
                html_parts.append(f'<td>{protocol}</td>')
                html_parts.append(f'<td>{html.escape(ports)}</td>')
                html_parts.append('</tr>')
        
        else:
            # Generic table for IP addresses or other items
            html_parts.append('<thead><tr>')
            html_parts.append('<th>Item</th>')
            html_parts.append('</tr></thead>')
            html_parts.append('<tbody>')
            
            for item in items[:10]:
                if isinstance(item, dict):
                    # Try to find a meaningful display value
                    display = item.get('address') or item.get('name') or item.get('display') or str(item)
                    web_url = item.get('web_url', '')
                else:
                    display = str(item)
                    web_url = ''
                
                html_parts.append('<tr>')
                if web_url:
                    html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{html.escape(str(display))}</a></td>')
                else:
                    html_parts.append(f'<td>{html.escape(str(display))}</td>')
                html_parts.append('</tr>')
        
        if len(items) > 10:
            html_parts.append('<tr>')
            html_parts.append(f'<td colspan="4" style="font-style: italic; color: #6c757d; text-align: center;">... and {len(items) - 10} more</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</tbody></table>')
        return '\n'.join(html_parts)

    def _format_checkmk_services_table(self, services: list) -> str:
        """Format CheckMK services in a compact table with clickable links."""
        if not services:
            return ''
        
        html_parts = ['<table style="margin-top: 5px;">']
        html_parts.append('<thead><tr>')
        html_parts.append('<th>Service</th>')
        html_parts.append('<th>State</th>')
        html_parts.append('<th>Output</th>')
        html_parts.append('</tr></thead>')
        html_parts.append('<tbody>')
        
        for service in services:
            extensions = service.get('extensions', {})
            description = html.escape(str(extensions.get('description', '-')))
            state = extensions.get('state')
            plugin_output = html.escape(str(extensions.get('plugin_output', '-')))
            web_url = service.get('web_url', '')
            
            # Map state to status indicator and class
            state_map = {
                0: ('✓ OK', 'state-open'),
                1: ('⚠ WARNING', 'state-filtered'),
                2: ('✗ CRITICAL', 'state-closed'),
                3: ('? UNKNOWN', '')
            }
            state_text, state_class = state_map.get(state, ('UNKNOWN', ''))
            
            html_parts.append('<tr>')
            # Make service description clickable if URL is available
            if web_url:
                html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{description}</a></td>')
            else:
                html_parts.append(f'<td style="color: #007acc;">{description}</td>')
            html_parts.append(f'<td class="{state_class}">{html.escape(state_text)}</td>')
            html_parts.append(f'<td>{plugin_output}</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</tbody></table>')
        return '\n'.join(html_parts)

    def _format_checkmk_hosts_table(self, hosts: list) -> str:
        """Format CheckMK hosts in a compact table with clickable links."""
        if not hosts:
            return ''
        
        html_parts = ['<table style="margin-top: 5px;">']
        html_parts.append('<thead><tr>')
        html_parts.append('<th>Host</th>')
        html_parts.append('<th>State</th>')
        html_parts.append('<th>Address</th>')
        html_parts.append('</tr></thead>')
        html_parts.append('<tbody>')
        
        for host in hosts[:10]:
            title = html.escape(str(host.get('title', '-')))
            extensions = host.get('extensions', {})
            state = extensions.get('state')
            address = html.escape(str(extensions.get('address', '-')))
            web_url = host.get('web_url', '')
            
            # Map state to status
            state_map = {
                0: ('✓ UP', 'state-open'),
                1: ('✗ DOWN', 'state-closed'),
                2: ('? UNREACHABLE', 'state-filtered')
            }
            state_text, state_class = state_map.get(state, ('UNKNOWN', ''))
            
            html_parts.append('<tr>')
            # Make host title clickable if URL is available
            if web_url:
                html_parts.append(f'<td><a href="{html.escape(web_url)}" target="_blank" style="color: #007acc; text-decoration: none;">{title}</a></td>')
            else:
                html_parts.append(f'<td style="color: #007acc;">{title}</td>')
            html_parts.append(f'<td class="{state_class}">{html.escape(state_text)}</td>')
            html_parts.append(f'<td>{address}</td>')
            html_parts.append('</tr>')
        
        if len(hosts) > 10:
            html_parts.append('<tr>')
            html_parts.append(f'<td colspan="3" style="font-style: italic; color: #6c757d; text-align: center;">... and {len(hosts) - 10} more</td>')
            html_parts.append('</tr>')
        
        html_parts.append('</tbody></table>')
        return '\n'.join(html_parts)

    def _extract_display_info_html(self, item: dict, category: str) -> str:
        """
        Extract key display information from an item for HTML display.

        Args:
            item: Dictionary item to extract info from
            category: Category name

        Returns:
            HTML formatted display string
        """
        # Try to find meaningful display information
        if 'name' in item:
            return html.escape(str(item['name']))
        elif 'title' in item:
            return html.escape(str(item['title']))
        elif 'address' in item:
            return html.escape(str(item['address']))
        elif 'display' in item:
            return html.escape(str(item['display']))
        else:
            return html.escape(str(item)[:100])  # Truncate long strings

    def _format_traceroute_tree_html(self, traceroute_results: list) -> str:
        """
        Format traceroute results as a tree-like visualization in HTML.

        Args:
            traceroute_results: List of traceroute results

        Returns:
            HTML string with tree visualization
        """
        if not traceroute_results:
            return '<div class="no-results">no traceroute results</div>'

        html_parts = ['<div class="key-value">']
        html_parts.append('<span class="key">Traceroute:</span>')
        html_parts.append('<div class="traceroute-tree">')

        for trace_result in traceroute_results:
            method = html.escape(trace_result.get('method', 'unknown').upper())
            success = trace_result.get('success', False)
            hops = trace_result.get('hops', [])
            error = trace_result.get('error')

            # Method header
            status_symbol = '✓' if success else '✗'
            html_parts.append(f'<div class="traceroute-method">{status_symbol} Method: {method}</div>')

            if error:
                html_parts.append(f'<div class="traceroute-hop failed">Error: {html.escape(str(error))}</div>')
                continue

            if not hops:
                html_parts.append('<div class="traceroute-hop">No hops recorded</div>')
                continue

            # Tree visualization for hops
            for i, hop in enumerate(hops):
                is_last = (i == len(hops) - 1)
                hop_num = hop.get('hop', hop.get('ttl', i + 1))
                ip = hop.get('ip', '*')
                hostname = hop.get('hostname', '')
                rtt = hop.get('rtt')
                reached_dest = hop.get('reached_destination', False)

                # Tree characters
                tree_char = '└──' if is_last else '├──'

                # Build hop line
                hop_class = 'destination' if reached_dest else ('failed' if ip == '*' else '')
                hop_str = f"{tree_char} Hop {hop_num}: "

                if ip and ip != '*':
                    hop_str += html.escape(ip)
                else:
                    hop_str += "* * *"

                if hostname and hostname != ip:
                    hop_str += f" ({html.escape(hostname)})"

                if rtt is not None:
                    hop_str += f" - {rtt:.2f}ms"

                if reached_dest:
                    hop_str += " [DESTINATION]"

                html_parts.append(f'<div class="traceroute-hop {hop_class}">{hop_str}</div>')

        html_parts.append('</div>')
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
