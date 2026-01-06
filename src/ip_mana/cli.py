"""
Command-line interface for IP Intelligence Analyzer.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import ConfigManager, ClassificationRule


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="ip-mana",
        description="IP Intelligence Analyzer - Comprehensive IP address analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("ip_address", nargs='?', help="IP address to analyze (IPv4 or IPv6)")

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
        help="Add new IP classification rule (QUALIFIES_FOR is comma-separated list)",
    )
    parser.add_argument(
        "--delete-classification",
        type=str,
        metavar="NAME",
        help="Delete IP classification rule by name",
    )
    parser.add_argument(
        "--list-classifications",
        action="store_true",
        help="List all classification rules",
    )
    parser.add_argument(
        "--update-classification",
        nargs=5,
        metavar=("OLD_NAME", "NEW_NAME", "IP_RANGE", "DESCRIPTION", "QUALIFIES_FOR"),
        help="Update existing IP classification rule",
    )

    # Verbose output
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output for debugging",
    )

    return parser


def handle_classification_management(args, config_manager: ConfigManager) -> int:
    """Handle classification CRUD operations."""
    try:
        if args.add_classification:
            name, ip_range, description, qualifies_for_str = args.add_classification
            qualifies_for = [m.strip() for m in qualifies_for_str.split(',')]
            
            rule = ClassificationRule(
                name=name,
                ip_range=ip_range,
                description=description,
                qualifies_for=qualifies_for
            )
            
            config_manager.add_classification(rule)
            print(f"Successfully added classification rule: {name}")
            return 0
            
        elif args.delete_classification:
            if config_manager.remove_classification(args.delete_classification):
                print(f"Successfully deleted classification rule: {args.delete_classification}")
            else:
                print(f"Classification rule not found: {args.delete_classification}")
                return 1
            return 0
            
        elif args.update_classification:
            old_name, new_name, ip_range, description, qualifies_for_str = args.update_classification
            qualifies_for = [m.strip() for m in qualifies_for_str.split(',')]
            
            updated_rule = ClassificationRule(
                name=new_name,
                ip_range=ip_range,
                description=description,
                qualifies_for=qualifies_for
            )
            
            if config_manager.update_classification(old_name, updated_rule):
                print(f"Successfully updated classification rule: {old_name} -> {new_name}")
            else:
                print(f"Classification rule not found: {old_name}")
                return 1
            return 0
            
        elif args.list_classifications:
            rules = config_manager.load_classifications()
            if not rules:
                print("No classification rules found.")
                return 0
                
            print("Classification Rules:")
            print("-" * 80)
            for name, rule in rules.items():
                print(f"Name: {rule.name}")
                print(f"IP Range: {rule.ip_range}")
                print(f"Description: {rule.description}")
                print(f"Qualifies For: {', '.join(rule.qualifies_for)}")
                if rule.rfc_reference:
                    print(f"RFC Reference: {rule.rfc_reference}")
                print("-" * 80)
            return 0
            
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    
    return 0


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI application."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    # Initialize configuration manager
    config_path = Path(parsed_args.config) if parsed_args.config else None
    config_manager = ConfigManager(config_path=config_path)

    # Handle classification management operations
    if any([parsed_args.add_classification, parsed_args.delete_classification, 
            parsed_args.list_classifications, parsed_args.update_classification]):
        return handle_classification_management(parsed_args, config_manager)

    # Require IP address for analysis operations
    if not parsed_args.ip_address:
        parser.error("IP address is required for analysis operations")

    # TODO: Implement main application logic
    print(f"IP-ManA v{__version__}")
    print(f"Analyzing IP: {parsed_args.ip_address}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
