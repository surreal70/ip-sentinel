"""
Human-readable console output formatter.
"""

from typing import Any
from datetime import datetime
import sys

from .base import OutputFormatter, VerbosityMode

# Try to import colorama for color support
try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback: no colors
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""


class HumanFormatter(OutputFormatter):
    """Formatter for human-readable console output."""

    def __init__(self, reporting_mode: str = "dense"):
        """
        Initialize the human formatter.

        Args:
            reporting_mode: Reporting mode (dense, full, full-err)
        """
        super().__init__(reporting_mode)
        # Check if terminal supports colors
        self.use_colors = COLORS_AVAILABLE and self._supports_color()

    def _supports_color(self) -> bool:
        """
        Check if the terminal supports color output.

        Returns:
            True if colors are supported, False otherwise
        """
        # Check if stdout is a terminal
        if not hasattr(sys.stdout, 'isatty'):
            return False
        if not sys.stdout.isatty():
            return False

        # Windows terminals with colorama support colors
        # Unix terminals typically support colors
        return True

    def _get_terminal_width(self) -> int:
        """
        Get the current terminal width.

        Returns:
            Terminal width in characters (default: 80)
        """
        try:
            import shutil
            width = shutil.get_terminal_size().columns
            return width if width > 0 else 80
        except Exception:
            return 80

    def _wrap_text(self, text: str, width: int, indent: int = 0, 
                   subsequent_indent: int = None) -> str:
        """
        Wrap text to fit within specified width.

        Args:
            text: Text to wrap
            width: Maximum width
            indent: Indentation for first line
            subsequent_indent: Indentation for subsequent lines (defaults to indent)

        Returns:
            Wrapped text with proper indentation
        """
        import textwrap
        
        if subsequent_indent is None:
            subsequent_indent = indent
        
        # Calculate available width after indentation
        available_width = width - indent
        if available_width < 20:  # Minimum reasonable width
            available_width = 20
        
        # Wrap the text
        wrapper = textwrap.TextWrapper(
            width=available_width,
            initial_indent='',
            subsequent_indent=' ' * (subsequent_indent - indent),
            break_long_words=False,
            break_on_hyphens=False
        )
        
        wrapped = wrapper.fill(text)
        
        # Add indentation to all lines
        indent_str = ' ' * indent
        lines = wrapped.split('\n')
        return '\n'.join(indent_str + line for line in lines)

    def _colorize(self, text: str, color: str = "", style: str = "") -> str:
        """
        Apply color and style to text if colors are enabled.

        Args:
            text: Text to colorize
            color: Color code from Fore
            style: Style code from Style

        Returns:
            Colorized text or plain text if colors disabled
        """
        if not self.use_colors:
            return text
        return f"{style}{color}{text}{Style.RESET_ALL}"

    def _section_header(self, title: str, char: str = "─") -> str:
        """
        Create a formatted section header.

        Args:
            title: Section title
            char: Character to use for underline

        Returns:
            Formatted header string
        """
        header = f"\n{self._colorize(title, Fore.CYAN, Style.BRIGHT)}"
        underline = char * len(title)
        return f"{header}\n{self._colorize(underline, Fore.CYAN)}"

    def _format_key_value(self, key: str, value: Any, indent: int = 2) -> str:
        """
        Format a key-value pair with proper indentation and styling.

        Args:
            key: Key name
            value: Value to display
            indent: Indentation level (spaces)

        Returns:
            Formatted key-value string
        """
        spaces = " " * indent
        formatted_key = self._colorize(f"{key}:", Fore.YELLOW)
        return f"{spaces}{formatted_key} {value}"

    def _format_list_item(self, item: str, indent: int = 2, bullet: str = "•") -> str:
        """
        Format a list item with bullet point.

        Args:
            item: Item text
            indent: Indentation level (spaces)
            bullet: Bullet character

        Returns:
            Formatted list item string
        """
        spaces = " " * indent
        colored_bullet = self._colorize(bullet, Fore.GREEN)
        return f"{spaces}{colored_bullet} {item}"

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

        # Header with enhanced styling
        ip_addr = data.get('ip_address', 'Unknown IP')
        timestamp = data.get('scan_timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp_str = timestamp
        else:
            timestamp_str = timestamp.strftime(
                '%Y-%m-%d %H:%M:%S') if hasattr(timestamp, 'strftime') else str(timestamp)

        header_line = "═" * 70
        output_lines.append(self._colorize(header_line, Fore.BLUE, Style.BRIGHT))
        output_lines.append(self._colorize("  IP INTELLIGENCE ANALYSIS REPORT", Fore.WHITE, Style.BRIGHT))
        output_lines.append(self._colorize(header_line, Fore.BLUE, Style.BRIGHT))
        output_lines.append(self._format_key_value("IP Address", self._colorize(ip_addr, Fore.GREEN, Style.BRIGHT), 2))
        output_lines.append(self._format_key_value("Scan Time", timestamp_str, 2))
        output_lines.append("")

        # Classifications with improved formatting
        if 'classifications' in filtered_data:
            classifications = filtered_data['classifications']
            if self._has_meaningful_data(classifications):
                output_lines.append(self._section_header("📋 Classifications"))
                if isinstance(classifications, list):
                    for classification in classifications:
                        # Parse classification details if it's a dict
                        if isinstance(classification, dict):
                            name = classification.get('name', 'Unknown')
                            ip_range = classification.get('ip_range', '')
                            description = classification.get('description', '')
                            qualifies_for = classification.get('qualifies_for', [])

                            output_lines.append(self._format_list_item(
                                self._colorize(name, Fore.CYAN, Style.BRIGHT), indent=2))
                            if ip_range:
                                output_lines.append(self._format_key_value("Range", ip_range, 4))
                            if description:
                                output_lines.append(self._format_key_value("Description", description, 4))
                            if qualifies_for:
                                modules_str = ", ".join(qualifies_for)
                                output_lines.append(self._format_key_value("Qualifies For", modules_str, 4))
                        else:
                            output_lines.append(self._format_list_item(str(classification)))
                else:
                    output_lines.append(self._format_list_item(str(classifications)))
                output_lines.append("")
            elif self.verbosity_mode in [VerbosityMode.FULL, VerbosityMode.FULL_ERR]:
                output_lines.append(self._section_header("📋 Classifications"))
                output_lines.append(self._colorize("  no results", Fore.YELLOW, Style.DIM))
                output_lines.append("")

        # Local Information with enhanced formatting
        if 'local_info' in filtered_data:
            local_info = filtered_data['local_info']
            if self._has_meaningful_data(
                    local_info) or self.verbosity_mode != VerbosityMode.DENSE:
                output_lines.append(self._section_header("🏠 Local Network Information"))
                if local_info == "no results":
                    output_lines.append(self._colorize("  no results", Fore.YELLOW, Style.DIM))
                elif isinstance(local_info, dict):
                    # Format local network information with better structure
                    for key, value in local_info.items():
                        formatted_key = key.replace('_', ' ').title()

                        # Special formatting for specific fields
                        if key == 'is_local_subnet':
                            status = self._colorize("Yes", Fore.GREEN) if value else self._colorize("No", Fore.RED)
                            output_lines.append(self._format_key_value(formatted_key, status))
                        elif key == 'reachable':
                            status = self._colorize("✓ Reachable", Fore.GREEN) if value else self._colorize("✗ Unreachable", Fore.RED)
                            output_lines.append(self._format_key_value(formatted_key, status))
                        elif key == 'mac_address' and isinstance(value, dict):
                            output_lines.append(self._format_key_value(formatted_key, ""))
                            for mac_key, mac_value in value.items():
                                mac_formatted_key = mac_key.replace('_', ' ').title()
                                if mac_key == 'is_gateway':
                                    gateway_status = self._colorize("Yes (Gateway/Router)", Fore.CYAN) if mac_value else "No"
                                    output_lines.append(self._format_key_value(mac_formatted_key, gateway_status, 4))
                                else:
                                    output_lines.append(self._format_key_value(mac_formatted_key, mac_value, 4))
                        elif key == 'nmap_results' and isinstance(value, dict):
                            output_lines.append(self._format_key_value(formatted_key, ""))
                            self._format_nmap_results(value, output_lines)
                        elif key == 'nat_detection' and isinstance(value, dict):
                            output_lines.append(self._format_key_value(formatted_key, ""))
                            self._format_nat_detection(value, output_lines)
                        elif key == 'ssl_results' and isinstance(value, list):
                            # Use custom SSL formatting
                            self._format_ssl_results(value, output_lines)
                        elif key == 'traceroute_results' and isinstance(value, list):
                            # Use tree visualization for traceroute
                            self._format_traceroute_tree(value, output_lines)
                        elif isinstance(value, list) and value:
                            output_lines.append(self._format_key_value(formatted_key, ""))
                            for item in value:
                                if isinstance(item, dict):
                                    for item_key, item_value in item.items():
                                        item_formatted_key = item_key.replace('_', ' ').title()
                                        output_lines.append(self._format_key_value(item_formatted_key, item_value, 4))
                                else:
                                    output_lines.append(self._format_list_item(str(item), indent=4))
                        else:
                            output_lines.append(self._format_key_value(formatted_key, value))
                else:
                    output_lines.append(f"  {local_info}")
                output_lines.append("")

        # Internet Information
        if 'internet_info' in filtered_data:
            internet_info = filtered_data['internet_info']
            if self._has_meaningful_data(
                    internet_info) or self.verbosity_mode != VerbosityMode.DENSE:
                output_lines.append(self._section_header("🌐 Internet Information"))
                if internet_info == "no results":
                    output_lines.append(self._colorize("  no results", Fore.YELLOW, Style.DIM))
                elif isinstance(internet_info, dict):
                    self._format_internet_info(internet_info, output_lines)
                else:
                    output_lines.append(f"  {internet_info}")
                output_lines.append("")

        # Application Information
        if 'application_info' in filtered_data:
            app_info = filtered_data['application_info']
            if self._has_meaningful_data(
                    app_info) or self.verbosity_mode != VerbosityMode.DENSE:
                output_lines.append(self._section_header("🔧 Application Information"))
                if app_info == "no results" or not app_info:
                    output_lines.append(self._colorize("  no results", Fore.YELLOW, Style.DIM))
                elif isinstance(app_info, dict):
                    self._format_application_info(app_info, output_lines)
                else:
                    output_lines.append(f"  {app_info}")
                output_lines.append("")

        # Errors (only in full-err mode or if there are errors in other modes)
        if 'errors' in filtered_data:
            errors = filtered_data['errors']
            if (self.verbosity_mode == VerbosityMode.FULL_ERR or (
                    self._has_meaningful_data(errors) and self.verbosity_mode != VerbosityMode.DENSE)):
                output_lines.append(self._section_header("⚠️  Errors and Issues"))
                if not self._has_meaningful_data(errors):
                    output_lines.append(self._colorize("  no errors", Fore.GREEN))
                elif isinstance(errors, list):
                    for error in errors:
                        output_lines.append(self._format_list_item(
                            self._colorize(str(error), Fore.RED), bullet="⚠"))
                else:
                    output_lines.append(self._format_list_item(
                        self._colorize(str(errors), Fore.RED), bullet="⚠"))
                output_lines.append("")

        # Footer
        footer_line = "═" * 70
        output_lines.append(self._colorize(footer_line, Fore.BLUE, Style.BRIGHT))

        return "\n".join(output_lines)

    def _format_nmap_results(self, nmap_data: dict, output_lines: list) -> None:
        """
        Format nmap results with better structure.

        Args:
            nmap_data: Nmap results dictionary
            output_lines: List to append formatted lines to
        """
        # Host status
        host_up = nmap_data.get('host_up', False)
        status = self._colorize("✓ Up", Fore.GREEN) if host_up else self._colorize("✗ Down", Fore.RED)
        output_lines.append(self._format_key_value("Host Status", status, 4))

        # OS detection
        os_detection = nmap_data.get('os_detection', {})
        if os_detection:
            if 'note' in os_detection:
                output_lines.append(self._format_key_value("OS Detection", 
                    self._colorize(os_detection['note'], Fore.YELLOW, Style.DIM), 4))
            elif 'matches' in os_detection and os_detection['matches']:
                output_lines.append(self._format_key_value("OS Detection", "", 4))
                for match in os_detection['matches'][:3]:  # Show top 3 matches
                    name = match.get('name', 'Unknown')
                    accuracy = match.get('accuracy', 0)
                    output_lines.append(self._format_list_item(
                        f"{name} ({accuracy}% accuracy)", indent=6, bullet="→"))

        # Open ports
        open_ports = nmap_data.get('open_ports', [])
        if open_ports:
            output_lines.append(self._format_key_value("Open Ports", f"{len(open_ports)} found", 4))
            for port_info in open_ports[:10]:  # Show first 10 ports
                port = port_info.get('port', '?')
                service = port_info.get('service', 'unknown')
                version = port_info.get('version', '')
                port_str = f"{port}/{port_info.get('protocol', 'tcp')}"
                service_str = f"{service}"
                if version:
                    service_str += f" ({version})"
                output_lines.append(self._format_list_item(
                    f"{self._colorize(port_str, Fore.CYAN)}: {service_str}", indent=6, bullet="→"))

    def _format_nat_detection(self, nat_data: dict, output_lines: list) -> None:
        """
        Format NAT detection results.

        Args:
            nat_data: NAT detection results dictionary
            output_lines: List to append formatted lines to
        """
        detected = nat_data.get('detected', False)
        private_ip = nat_data.get('private_ip', 'Unknown')
        public_ip = nat_data.get('public_ip', 'Unknown')
        nat_type = nat_data.get('nat_type')
        error = nat_data.get('error')

        if error:
            output_lines.append(self._format_key_value("Status", 
                self._colorize(f"Error: {error}", Fore.RED), 4))
            return

        if detected:
            status = self._colorize("✓ NAT Detected", Fore.GREEN, Style.BRIGHT)
            output_lines.append(self._format_key_value("Status", status, 4))
            output_lines.append(self._format_key_value("Private IP", private_ip, 4))
            output_lines.append(self._format_key_value("Public IP", 
                self._colorize(public_ip, Fore.CYAN), 4))
            if nat_type:
                output_lines.append(self._format_key_value("NAT Type", nat_type, 4))
        else:
            status = self._colorize("✗ No NAT Detected", Fore.YELLOW)
            output_lines.append(self._format_key_value("Status", status, 4))

    def _format_ssl_results(self, ssl_results: list, output_lines: list) -> None:
        """
        Format SSL/TLS results in a human-readable way.

        Args:
            ssl_results: List of SSL result dictionaries
            output_lines: List to append formatted lines to
        """
        if not ssl_results:
            return

        output_lines.append(self._format_key_value("Ssl Results", ""))

        for ssl_result in ssl_results:
            port = ssl_result.get('port', 'Unknown')
            protocol = ssl_result.get('protocol', 'Unknown')
            certificate = ssl_result.get('certificate')
            cipher_suites = ssl_result.get('cipher_suites', [])
            vulnerabilities = ssl_result.get('vulnerabilities', [])

            # Port header
            output_lines.append(self._format_key_value("Port", self._colorize(str(port), Fore.CYAN), 4))
            output_lines.append(self._format_key_value("Protocol", protocol, 4))

            # Certificate information
            if certificate:
                if isinstance(certificate, dict):
                    # Check if this is a reference to another port
                    if 'reference_to_port' in certificate:
                        ref_port = certificate['reference_to_port']
                        note = certificate.get('note', 'See primary port for details')
                        output_lines.append(self._format_key_value("Certificate", 
                            self._colorize(f"→ Same as port {ref_port} ({note})", Fore.YELLOW, Style.DIM), 4))
                    else:
                        output_lines.append(self._format_key_value("Certificate", "", 4))
                        
                        # Extract readable certificate fields
                        subject = certificate.get('subject', 'Unknown')
                        issuer = certificate.get('issuer', 'Unknown')
                        not_valid_before = certificate.get('not_valid_before', 'Unknown')
                        not_valid_after = certificate.get('not_valid_after', 'Unknown')
                        shared_ports = certificate.get('shared_across_ports', [])
                        
                        # Clean up subject and issuer (remove <Name(...)> wrapper)
                        if isinstance(subject, str) and subject.startswith('<Name(') and subject.endswith(')>'):
                            subject = subject[6:-2]
                        if isinstance(issuer, str) and issuer.startswith('<Name(') and issuer.endswith(')>'):
                            issuer = issuer[6:-2]
                        
                        output_lines.append(self._format_key_value("Subject", 
                            self._colorize(subject, Fore.GREEN), 6))
                        output_lines.append(self._format_key_value("Issuer", issuer, 6))
                        output_lines.append(self._format_key_value("Valid From", not_valid_before, 6))
                        output_lines.append(self._format_key_value("Valid Until", not_valid_after, 6))
                        
                        if shared_ports and len(shared_ports) > 1:
                            ports_str = ', '.join(map(str, shared_ports))
                            output_lines.append(self._format_key_value("Shared Across Ports", 
                                self._colorize(ports_str, Fore.CYAN), 6))
            else:
                output_lines.append(self._format_key_value("Certificate", 
                    self._colorize("None", Fore.YELLOW, Style.DIM), 4))

            # Cipher suites
            if cipher_suites:
                count = len(cipher_suites)
                output_lines.append(self._format_key_value("Cipher Suites", 
                    f"{count} supported", 4))
                for cipher in cipher_suites:
                    output_lines.append(f"        • {self._colorize(cipher, Fore.CYAN)}")
            else:
                output_lines.append(self._format_key_value("Cipher Suites", 
                    self._colorize("None detected", Fore.YELLOW, Style.DIM), 4))

            # Vulnerabilities
            if vulnerabilities:
                output_lines.append(self._format_key_value("Vulnerabilities", 
                    self._colorize(f"{len(vulnerabilities)} found", Fore.RED, Style.BRIGHT), 4))
                for vuln in vulnerabilities:
                    output_lines.append(f"        • {self._colorize(vuln, Fore.RED)}")
            else:
                output_lines.append(self._format_key_value("Vulnerabilities", 
                    self._colorize("✓ None detected", Fore.GREEN), 4))

            output_lines.append("")  # Blank line between SSL results

    def _format_internet_info(self, internet_info: dict, output_lines: list) -> None:
        """
        Format internet information in a human-readable way.

        Args:
            internet_info: Dictionary containing internet information
            output_lines: List to append formatted lines to
        """
        for key, value in internet_info.items():
            formatted_key = key.replace('_', ' ').title()
            
            # Special formatting for specific fields
            if key == 'whois_data' and isinstance(value, dict):
                output_lines.append(self._format_key_value(formatted_key, ""))
                for whois_key, whois_value in value.items():
                    if whois_value:  # Only show non-empty values
                        whois_formatted_key = whois_key.replace('_', ' ').title()
                        output_lines.append(self._format_key_value(whois_formatted_key, whois_value, 4))
            
            elif key == 'geolocation' and isinstance(value, dict):
                output_lines.append(self._format_key_value(formatted_key, ""))
                # Format location nicely
                country = value.get('country', 'Unknown')
                city = value.get('city', 'Unknown')
                region = value.get('region', '')
                
                location_str = f"{city}"
                if region and region != city:
                    location_str += f", {region}"
                location_str += f", {country}"
                
                output_lines.append(self._format_key_value("Location", 
                    self._colorize(location_str, Fore.GREEN), 4))
                
                # Coordinates
                lat = value.get('latitude')
                lon = value.get('longitude')
                if lat is not None and lon is not None:
                    output_lines.append(self._format_key_value("Coordinates", 
                        f"{lat}, {lon}", 4))
                
                # Timezone
                timezone = value.get('timezone')
                if timezone:
                    output_lines.append(self._format_key_value("Timezone", timezone, 4))
                
                # ISP
                isp = value.get('isp')
                if isp:
                    output_lines.append(self._format_key_value("ISP", 
                        self._colorize(isp, Fore.CYAN), 4))
            
            elif key == 'asn_info' and isinstance(value, dict):
                output_lines.append(self._format_key_value(formatted_key, ""))
                asn = value.get('asn', 'Unknown')
                description = value.get('description', 'Unknown')
                country = value.get('country', 'Unknown')
                registry = value.get('registry', 'Unknown')
                
                output_lines.append(self._format_key_value("ASN", 
                    self._colorize(f"AS{asn}", Fore.CYAN), 4))
                output_lines.append(self._format_key_value("Description", description, 4))
                output_lines.append(self._format_key_value("Country", country, 4))
                output_lines.append(self._format_key_value("Registry", registry.upper(), 4))
            
            elif key == 'blocklist_results' and isinstance(value, list):
                if value:
                    output_lines.append(self._format_key_value(formatted_key, 
                        self._colorize(f"{len(value)} blocklists", Fore.RED, Style.BRIGHT)))
                    for blocklist in value:
                        output_lines.append(f"    • {self._colorize(blocklist, Fore.RED)}")
                else:
                    output_lines.append(self._format_key_value(formatted_key, 
                        self._colorize("✓ Not listed", Fore.GREEN)))
            
            elif key == 'reputation_score':
                if isinstance(value, (int, float)):
                    # Color code based on score (0.0 = bad, 1.0 = good)
                    if value >= 0.8:
                        color = Fore.GREEN
                        status = "Good"
                    elif value >= 0.5:
                        color = Fore.YELLOW
                        status = "Fair"
                    else:
                        color = Fore.RED
                        status = "Poor"
                    
                    score_str = f"{value:.2f} ({status})"
                    output_lines.append(self._format_key_value(formatted_key, 
                        self._colorize(score_str, color)))
                else:
                    output_lines.append(self._format_key_value(formatted_key, value))
            
            elif key == 'reverse_dns':
                if value:
                    output_lines.append(self._format_key_value(formatted_key, 
                        self._colorize(value, Fore.CYAN)))
                else:
                    output_lines.append(self._format_key_value(formatted_key, 
                        self._colorize("None", Fore.YELLOW, Style.DIM)))
            
            elif isinstance(value, list) and value:
                output_lines.append(self._format_key_value(formatted_key, ""))
                for item in value:
                    output_lines.append(self._format_list_item(str(item), indent=4))
            
            else:
                output_lines.append(self._format_key_value(formatted_key, value))

    def _format_application_info(self, app_info: dict, output_lines: list) -> None:
        """
        Format application information in a human-readable way.

        Args:
            app_info: Dictionary containing application module results
            output_lines: List to append formatted lines to
        """
        for app_name, app_data in app_info.items():
            output_lines.append(self._format_list_item(
                self._colorize(app_name.upper(), Fore.MAGENTA, Style.BRIGHT)))
            
            if not isinstance(app_data, dict):
                output_lines.append(f"    {app_data}")
                continue
            
            # Extract standard fields
            success = app_data.get('success', False)
            error_message = app_data.get('error_message')
            source = app_data.get('source', 'Unknown')
            data = app_data.get('data')
            
            # Status
            if success:
                status_str = self._colorize("✓ Success", Fore.GREEN)
            else:
                status_str = self._colorize("✗ Failed", Fore.RED)
            output_lines.append(self._format_key_value("Status", status_str, 4))
            
            # Source
            output_lines.append(self._format_key_value("Source", 
                self._colorize(source, Fore.CYAN), 4))
            
            # Error message if present
            if error_message:
                output_lines.append(self._format_key_value("Error", 
                    self._colorize(error_message, Fore.RED), 4))
            
            # Data - format based on structure
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
                    output_lines.append(self._format_key_value("Found", 
                        self._colorize(summary, Fore.GREEN), 4))
                    
                    # Show details for each category
                    for key, value in data.items():
                        if isinstance(value, list) and value:
                            formatted_key = key.replace('_', ' ').title()
                            output_lines.append(self._format_key_value(formatted_key, 
                                f"{len(value)} items", 6))
                            
                            # For CheckMK services, show all items; for others, limit to 3
                            max_items = len(value) if key == 'services' else 3
                            
                            # Show items with key details
                            for i, item in enumerate(value[:max_items]):
                                if isinstance(item, dict):
                                    # Extract key identifying information
                                    display_info = self._extract_display_info(item, key)
                                    if display_info:
                                        output_lines.append(f"          • {display_info}")
                            
                            if len(value) > max_items:
                                remaining = len(value) - max_items
                                output_lines.append(f"          {self._colorize(f'... and {remaining} more', Fore.YELLOW, Style.DIM)}")
                else:
                    output_lines.append(self._format_key_value("Data", 
                        self._colorize("No items found", Fore.YELLOW, Style.DIM), 4))
            elif data:
                output_lines.append(self._format_key_value("Data", 
                    self._colorize("Available (see JSON output for details)", Fore.CYAN, Style.DIM), 4))
            else:
                output_lines.append(self._format_key_value("Data", 
                    self._colorize("None", Fore.YELLOW, Style.DIM), 4))
            
            output_lines.append("")  # Blank line between applications

    def _extract_display_info(self, item: dict, category: str) -> str:
        """
        Extract key display information from an item based on its category.

        Args:
            item: Dictionary item to extract info from
            category: Category name (e.g., 'prefixes', 'devices', 'services')

        Returns:
            Formatted display string
        """
        # CheckMK services - show description with state and output
        if category == 'services':
            extensions = item.get('extensions', {})
            description = extensions.get('description', '')
            state = extensions.get('state')
            plugin_output = extensions.get('plugin_output', '')
            
            # Map state to status indicator
            state_indicators = {
                0: self._colorize("✓", Fore.GREEN),      # OK
                1: self._colorize("⚠", Fore.YELLOW),     # WARNING
                2: self._colorize("✗", Fore.RED),        # CRITICAL
                3: self._colorize("?", Fore.CYAN)        # UNKNOWN
            }
            
            state_indicator = state_indicators.get(state, "")
            
            # Build display string
            if description and plugin_output:
                # Get terminal width and calculate available space
                terminal_width = self._get_terminal_width()
                # Account for: "          • " (12 chars) + state indicator (1-2 chars) + space
                base_indent = 12  # "          • "
                
                # Combine description and output
                full_text = f"{description}: {plugin_output}"
                
                # Wrap if text is too long
                available_width = terminal_width - base_indent - 2  # -2 for indicator + space
                if len(full_text) > available_width:
                    # Wrap text with minimal subsequent indent (just align with bullet)
                    wrapped = self._wrap_text(
                        full_text,
                        terminal_width,
                        indent=base_indent + 2,  # First line indent (bullet + indicator)
                        subsequent_indent=base_indent  # Wrapped lines align with bullet
                    ).strip()
                    
                    wrapped_lines = wrapped.split('\n')
                    if len(wrapped_lines) > 1:
                        # First line with indicator, rest without extra indent
                        return f"{state_indicator} {wrapped_lines[0]}\n" + '\n'.join(wrapped_lines[1:])
                    else:
                        return f"{state_indicator} {wrapped}"
                
                return f"{state_indicator} {full_text}"
            elif description:
                return f"{state_indicator} {description}"
            elif 'id' in item:
                # Extract service name from ID (format: "hostname:service_name")
                service_id = item['id']
                if ':' in service_id:
                    service_name = service_id.split(':', 1)[1]
                    if plugin_output:
                        return f"{state_indicator} {service_name}: {plugin_output}"
                    return f"{state_indicator} {service_name}"
                return service_id
        
        # Common fields to look for
        display = item.get('display')
        if display:
            return str(display)
        
        name = item.get('name')
        if name:
            # Add additional context if available
            if 'prefix' in item:
                return f"{name} ({item['prefix']})"
            elif 'ip_address' in item:
                return f"{name} ({item['ip_address']})"
            elif 'vid' in item:  # VLAN ID
                return f"{name} (VLAN {item['vid']})"
            return name
        
        # Category-specific extraction
        if category == 'prefixes' and 'prefix' in item:
            prefix = item['prefix']
            description = item.get('description', '')
            if description:
                return f"{prefix} - {description}"
            return prefix
        
        if category == 'ip_addresses' and 'address' in item:
            address = item['address']
            dns_name = item.get('dns_name', '')
            if dns_name:
                return f"{address} ({dns_name})"
            return address
        
        if category == 'devices' and 'name' in item:
            device_name = item['name']
            device_type = item.get('device_type', {}).get('display', '')
            if device_type:
                return f"{device_name} ({device_type})"
            return device_name
        
        if category == 'vlans':
            vid = item.get('vid')
            vlan_name = item.get('name', '')
            if vid and vlan_name:
                return f"VLAN {vid}: {vlan_name}"
            elif vid:
                return f"VLAN {vid}"
        
        # Fallback to first available string value
        for key in ['id', 'hostname', 'address', 'description']:
            if key in item and item[key]:
                return f"{key}: {item[key]}"
        
        return "Item"

    def _format_traceroute_tree(self, traceroute_results: list, output_lines: list) -> None:
        """
        Format traceroute results as a tree-like visualization.

        Args:
            traceroute_results: List of traceroute results
            output_lines: List to append formatted lines to
        """
        if not traceroute_results:
            return

        output_lines.append(self._format_key_value("Traceroute", ""))

        for trace_result in traceroute_results:
            method = trace_result.get('method', 'unknown')
            success = trace_result.get('success', False)
            hops = trace_result.get('hops', [])
            error = trace_result.get('error')

            # Method header
            method_str = f"Method: {method.upper()}"
            if success:
                status_str = self._colorize("✓", Fore.GREEN)
            else:
                status_str = self._colorize("✗", Fore.RED)

            output_lines.append(f"    {status_str} {self._colorize(method_str, Fore.CYAN)}")

            if error:
                output_lines.append(f"      {self._colorize(f'Error: {error}', Fore.RED, Style.DIM)}")
                continue

            if not hops:
                output_lines.append(f"      {self._colorize('No hops recorded', Fore.YELLOW, Style.DIM)}")
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
                if is_last:
                    tree_char = "└──"
                else:
                    tree_char = "├──"

                # Build hop line
                hop_str = f"{tree_char} Hop {hop_num}: "

                if ip and ip != '*':
                    hop_str += self._colorize(ip, Fore.GREEN if reached_dest else Fore.YELLOW)
                else:
                    hop_str += self._colorize("* * *", Fore.RED, Style.DIM)

                if hostname and hostname != ip:
                    hop_str += f" ({hostname})"

                if rtt is not None:
                    hop_str += f" - {rtt:.2f}ms"

                if reached_dest:
                    hop_str += self._colorize(" [DESTINATION]", Fore.GREEN, Style.BRIGHT)

                output_lines.append(f"      {hop_str}")
