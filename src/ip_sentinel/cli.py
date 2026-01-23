"""
Command-line interface for IP-Sentinel.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import ConfigManager, ClassificationRule, Config


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="ip-sentinel",
        description="IP-Sentinel - Comprehensive IP address analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "ip_address",
        nargs='?',
        help="IP address to analyze (IPv4 or IPv6)")

    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Output format options
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--human", action="store_true", help="Output results in human-readable format (default)"
    )
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
    parser.add_argument(
        "--credentials",
        type=str,
        help="Application Module credential file path (default: config/app_credentials.json)"
    )

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

    # Root privilege control
    parser.add_argument(
        "--run-root",
        action="store_true",
        help="Enable tests requiring root/administrator privileges (nmap OS detection, certain port scans)",
    )

    # SSL certificate verification control
    parser.add_argument(
        "--no-cert-check",
        action="store_true",
        help="Disable SSL certificate verification (WARNING: This is insecure and should only be used for testing)",
    )

    # Batch processing options
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Enable batch processing mode for multiple IP addresses from CIDR networks",
    )
    parser.add_argument(
        "--output-folder",
        type=str,
        help="Output folder for batch mode results (required with --batch)",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Enable parallel processing of IP addresses in batch mode",
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
                print(
                    f"Successfully deleted classification rule: {
                        args.delete_classification}")
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
                print(
                    f"Successfully updated classification rule: {old_name} -> {new_name}")
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


def handle_batch_mode(args, config_manager: ConfigManager) -> int:
    """
    Handle batch processing mode.

    Args:
        args: Parsed command-line arguments
        config_manager: Configuration manager instance

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    from .batch import BatchProcessor, BatchSizeExceededError, InvalidOutputFormatError, OutputFolderError
    from .analyzer import IPAnalyzer

    # Validate batch mode requirements
    # 1. Require --output-folder
    if not args.output_folder:
        print("Error: --output-folder is required in batch mode", file=sys.stderr)
        return 1

    # 2. Require JSON or HTML output format
    output_format = "human"
    if args.json:
        output_format = "json"
    elif args.html:
        output_format = "html"
    elif args.human:
        output_format = "human"

    if output_format not in ['json', 'html']:
        print(
            "Error: Batch mode requires --json or --html output format. "
            "Human-readable format is not supported in batch mode.",
            file=sys.stderr
        )
        return 1

    # Build configuration
    config = build_config_from_args(args)

    # Validate IP address is in CIDR notation (contains '/')
    if '/' not in args.ip_address:
        print(
            "Error: Batch mode requires CIDR notation (e.g., 192.168.1.0/24)",
            file=sys.stderr
        )
        return 1

    try:
        # Initialize analyzer
        with IPAnalyzer(
            config=config,
            config_manager=config_manager,
            credential_file=args.credentials
        ) as analyzer:

            # Initialize batch processor
            batch_processor = BatchProcessor(
                analyzer=analyzer,
                output_folder=args.output_folder,
                format_type=output_format,
                parallel=args.parallel
            )

            # Display batch mode information
            if args.verbose:
                print(f"IP-Sentinel v{__version__} - Batch Mode")
                print(f"CIDR Network: {args.ip_address}")
                print(f"Output Folder: {args.output_folder}")
                print(f"Output Format: {output_format}")
                print(f"Parallel Processing: {'Enabled' if args.parallel else 'Disabled'}")
                print(f"Reporting Mode: {config.reporting_mode}")
                print("-" * 80)

            # Process CIDR network
            result = batch_processor.process_cidr(args.ip_address)

            # Display summary
            print("\n" + "=" * 80)
            print("Batch Processing Summary")
            print("=" * 80)
            print(f"Total IPs Processed: {result.total_ips}")
            print(f"Successful: {result.successful}")
            print(f"Failed: {result.failed}")
            print(f"Duration: {result.duration:.2f} seconds")
            print(f"Output Files: {len(result.output_files)}")
            print(f"Output Folder: {args.output_folder}")
            print("=" * 80)

            # Display errors if any
            if result.errors:
                print("\nErrors encountered during batch processing:", file=sys.stderr)
                for ip_str, error_msg in result.errors.items():
                    print(f"  {ip_str}: {error_msg}", file=sys.stderr)

            # Return non-zero if any failures occurred
            return 1 if result.failed > 0 else 0

    except BatchSizeExceededError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except InvalidOutputFormatError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except OutputFolderError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI application."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    # Setup logging using analyzer's setup_logging function
    from .analyzer import setup_logging
    setup_logging(verbose=parsed_args.verbose)

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

    # Validate batch mode requirements
    if parsed_args.batch:
        return handle_batch_mode(parsed_args, config_manager)

    # Build configuration from command-line arguments
    config = build_config_from_args(parsed_args)

    # Initialize analyzer with context manager for proper cleanup
    try:
        from .analyzer import IPAnalyzer

        with IPAnalyzer(
            config=config,
            config_manager=config_manager,
            credential_file=parsed_args.credentials
        ) as analyzer:

            # Validate requested modules
            requested_modules = get_requested_modules(parsed_args)
            if requested_modules:
                availability = analyzer.validate_module_availability(requested_modules)
                unavailable = [m for m, avail in availability.items() if not avail]

                if unavailable:
                    print(
                        f"Warning: The following modules are not available: {
                            ', '.join(unavailable)}")
                    if parsed_args.verbose:
                        print(
                            "Available modules:", ', '.join(
                                analyzer.get_available_modules()))

            # Perform analysis
            if parsed_args.verbose:
                print(f"IP-Sentinel v{__version__}")
                print(f"Analyzing IP: {parsed_args.ip_address}")
                print(f"Output format: {config.output_format}")
                print(f"Reporting mode: {config.reporting_mode}")
                print(
                    f"Enabled modules: {[m for m, enabled in config.enabled_modules.items() if enabled]}")
                print("-" * 80)

            result = analyzer.analyze(parsed_args.ip_address)

            # Format and output results
            formatter = get_formatter(config.output_format, config.reporting_mode)
            output = formatter.format_result(result)
            print(output)

            # Report errors if any
            if result.errors:
                print("\nErrors encountered during analysis:", file=sys.stderr)
                for error in result.errors:
                    print(f"  - {error}", file=sys.stderr)
                return 1

            return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if parsed_args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def build_config_from_args(args) -> Config:
    """
    Build Config object from command-line arguments.

    Args:
        args: Parsed command-line arguments

    Returns:
        Config object
    """
    from .config import Config

    # Determine output format (human is default)
    output_format = "human"
    if args.json:
        output_format = "json"
    elif args.html:
        output_format = "html"
    elif args.human:
        output_format = "human"

    # Determine reporting mode
    reporting_mode = "dense"
    if args.full:
        reporting_mode = "full"
    elif args.full_err:
        reporting_mode = "full-err"

    # Determine enabled modules
    enabled_modules = {
        "classification": True,
        "local_info": True,
        "internet_info": True,
        "netbox": args.netbox,
        "checkmk": args.checkmk,
        "openitcockpit": args.openitcockpit,
        "openvas": args.openvas,
        "infoblox": args.infoblox,
    }

    # Determine force internet flag
    force_internet = args.force_internet or args.force_module3

    # Determine database path
    database_path = Path(args.db_path) if args.db_path else None

    # Determine SSL verification (inverse of no_cert_check)
    verify_ssl = not args.no_cert_check

    # Display warning if certificate verification is disabled
    if args.no_cert_check and args.verbose:
        print("WARNING: SSL certificate verification is disabled. This is insecure!")

    return Config(
        database_path=database_path,
        output_format=output_format,
        reporting_mode=reporting_mode,
        force_internet=force_internet,
        enabled_modules=enabled_modules,
        run_root=args.run_root,
        verify_ssl=verify_ssl,
        verbose=args.verbose
    )


def get_requested_modules(args) -> List[str]:
    """
    Get list of explicitly requested modules from arguments.

    Args:
        args: Parsed command-line arguments

    Returns:
        List of requested module names
    """
    requested = []

    if args.netbox:
        requested.append('netbox')
    if args.checkmk:
        requested.append('checkmk')
    if args.openitcockpit:
        requested.append('openitcockpit')
    if args.openvas:
        requested.append('openvas')
    if args.infoblox:
        requested.append('infoblox')

    return requested


def get_formatter(output_format: str, reporting_mode: str):
    """
    Get appropriate formatter based on output format and reporting mode.

    Args:
        output_format: Output format ('human', 'json', 'html')
        reporting_mode: Reporting mode ('dense', 'full', 'full-err')

    Returns:
        Formatter instance
    """
    from .formatters.human import HumanFormatter
    from .formatters.json import JSONFormatter
    from .formatters.html import HTMLFormatter

    if output_format == "json":
        return JSONFormatter(reporting_mode)
    elif output_format == "html":
        return HTMLFormatter(reporting_mode)
    else:
        return HumanFormatter(reporting_mode)


if __name__ == "__main__":
    sys.exit(main())
