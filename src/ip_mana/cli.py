"""
Command-line interface for IP Intelligence Analyzer.
"""

import argparse
import sys
from typing import List, Optional

from . import __version__


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="ip-mana",
        description="IP Intelligence Analyzer - Comprehensive IP address analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("ip_address", help="IP address to analyze (IPv4 or IPv6)")

    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Output format options
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )
    output_group.add_argument(
        "--html", action="store_true", help="Output results in HTML format"
    )

    # Reporting mode options
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--full",
        action="store_true",
        help="Show all tests including those with no results",
    )
    mode_group.add_argument(
        "--full-err",
        action="store_true",
        help="Show all tests including error details and timeouts",
    )

    # Database options
    parser.add_argument(
        "--db-path", type=str, help="Specify alternative database location"
    )

    # Module control options
    parser.add_argument(
        "--force-internet",
        action="store_true",
        help="Force execution of Internet Info Module (Module 3)",
    )
    parser.add_argument(
        "--force-module3", action="store_true", help="Alias for --force-internet"
    )

    # Module 4 submodule options
    parser.add_argument(
        "--netbox", action="store_true", help="Enable NetBox submodule (Module 4)"
    )
    parser.add_argument(
        "--checkmk", action="store_true", help="Enable CheckMK submodule (Module 4)"
    )
    parser.add_argument(
        "--openitcockpit",
        action="store_true",
        help="Enable OpenITCockpit submodule (Module 4)",
    )
    parser.add_argument(
        "--openvas", action="store_true", help="Enable OpenVAS submodule (Module 4)"
    )
    parser.add_argument(
        "--infoblox", action="store_true", help="Enable Infoblox submodule (Module 4)"
    )

    # Configuration options
    parser.add_argument("--config", type=str, help="Configuration file path")

    # Classification management
    parser.add_argument(
        "--add-classification",
        nargs=4,
        metavar=("NAME", "IP_RANGE", "DESCRIPTION", "QUALIFIES_FOR"),
        help="Add new IP classification rule",
    )
    parser.add_argument(
        "--delete-classification",
        type=str,
        metavar="NAME",
        help="Delete IP classification rule by name",
    )

    # Verbose output
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output for debugging",
    )

    return parser


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI application."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    # TODO: Implement main application logic
    print(f"IP-ManA v{__version__}")
    print(f"Analyzing IP: {parsed_args.ip_address}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
