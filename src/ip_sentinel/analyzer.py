"""
Main application controller for IP-Sentinel.

This module provides comprehensive integration of all analysis modules with:
- Graceful error handling and degradation
- Configurable logging with verbosity levels
- Result aggregation and correlation
- Proper resource cleanup and management
"""

import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Dict, List, Optional, Union, Any

from .config import Config, ConfigManager
from .ip_handler import IPAddressHandler
from .modules.classification import ClassificationModule
from .modules.local_info import LocalInfoModule
from .modules.internet_info import InternetInfoModule
from .modules.application import ApplicationModule
from .database.manager import DatabaseManager

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False, log_file: Optional[str] = None):
    """
    Configure logging system with appropriate verbosity level.

    Args:
        verbose: Enable verbose (DEBUG) logging
        log_file: Optional file path for log output
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    handlers = [logging.StreamHandler(sys.stderr)]

    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=handlers
    )

    # Reduce noise from external libraries
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)


@dataclass
class AnalysisResult:
    """Container for complete IP analysis results."""

    ip_address: Union[IPv4Address, IPv6Address]
    scan_timestamp: datetime
    classifications: List[Dict[str, Any]]
    local_info: Optional[Dict[str, Any]]
    internet_info: Optional[Dict[str, Any]]
    application_info: Dict[str, Dict[str, Any]]
    errors: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert the analysis result to a dictionary."""
        return {
            'ip_address': str(self.ip_address),
            'scan_timestamp': self.scan_timestamp.isoformat(),
            'classifications': self.classifications,
            'local_info': self.local_info,
            'internet_info': self.internet_info,
            'application_info': self.application_info,
            'errors': self.errors
        }


class IPAnalyzer:
    """Main controller class for IP intelligence analysis."""

    def __init__(self, config: Config, config_manager: Optional[ConfigManager] = None,
                 credential_file: Optional[str] = None):
        """
        Initialize the analyzer with configuration.

        Args:
            config: Application configuration
            config_manager: Configuration manager for classifications
            credential_file: Path to application module credentials file
        """
        self.config = config
        self.config_manager = config_manager or ConfigManager()
        self.credential_file = credential_file
        self.errors: List[str] = []

        logger.info("Initializing IP-Sentinel")

        # Initialize modules with error handling
        try:
            self.classification_module = ClassificationModule(self.config_manager)
            logger.debug("Classification module initialized")
        except Exception as e:
            logger.error(f"Failed to initialize classification module: {e}")
            self.classification_module = None
            self.errors.append(f"Classification module initialization failed: {e}")

        try:
            self.local_info_module = LocalInfoModule(
                run_root=self.config.run_root,
                verify_ssl=self.config.verify_ssl
            )
            logger.debug("Local info module initialized")
        except Exception as e:
            logger.error(f"Failed to initialize local info module: {e}")
            self.local_info_module = None
            self.errors.append(f"Local info module initialization failed: {e}")

        try:
            self.internet_info_module = InternetInfoModule(verify_ssl=self.config.verify_ssl)
            logger.debug("Internet info module initialized")
        except Exception as e:
            logger.error(f"Failed to initialize internet info module: {e}")
            self.internet_info_module = None
            self.errors.append(f"Internet info module initialization failed: {e}")

        try:
            self.application_module = ApplicationModule(
                credential_file,
                verify_ssl=self.config.verify_ssl
            )
            logger.debug("Application module initialized")
        except Exception as e:
            logger.error(f"Failed to initialize application module: {e}")
            self.application_module = None
            self.errors.append(f"Application module initialization failed: {e}")

        # Initialize database manager if database path is configured
        self.database_manager = None
        if config.database_path:
            try:
                self.database_manager = DatabaseManager(config.database_path)
                logger.info(f"Database initialized at: {config.database_path}")
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                self.errors.append(f"Database initialization failed: {e}")

        if self.errors:
            logger.warning(f"Analyzer initialized with {len(self.errors)} error(s)")
        else:
            logger.info("Analyzer initialized successfully")

    def analyze(self, ip_address: str) -> AnalysisResult:
        """
        Perform comprehensive analysis of an IP address.

        This method coordinates all analysis modules, handles errors gracefully,
        aggregates results, and ensures proper resource cleanup.

        Args:
            ip_address: String representation of IP address to analyze

        Returns:
            AnalysisResult containing all gathered intelligence
        """
        start_time = datetime.now()
        errors = list(self.errors)  # Include initialization errors

        logger.info("=" * 80)
        logger.info(f"Starting analysis for IP address: {ip_address}")
        logger.info("=" * 80)

        # Validate IP address
        try:
            ip_obj = IPAddressHandler.validate_ip(ip_address)
            ip_version = "IPv6" if isinstance(ip_obj, IPv6Address) else "IPv4"
            logger.info(f"IP address validated: {ip_obj} ({ip_version})")
        except (ValueError, Exception) as e:
            error_msg = f"Invalid IP address: {e}"
            logger.error(error_msg)
            return AnalysisResult(
                ip_address=None,
                scan_timestamp=start_time,
                classifications=[],
                local_info=None,
                internet_info=None,
                application_info={},
                errors=[error_msg]
            )

        # Module 1: Classification
        classifications = []
        qualified_modules = []
        if self.classification_module:
            try:
                logger.info("Running Classification Module (Module 1)")
                classifications = self.classification_module.classify_ip(ip_obj)
                qualified_modules = self.classification_module.get_qualified_modules(
                    classifications)
                logger.info(f"Classifications: {[c['name'] for c in classifications]}")
                logger.info(f"Qualified modules: {qualified_modules}")
            except Exception as e:
                error_msg = f"Classification module error: {e}"
                logger.error(error_msg, exc_info=True)
                errors.append(error_msg)
        else:
            logger.warning("Classification module not available, skipping")

        # Module 2: Local Information
        local_info = None
        if self.local_info_module and self.config.enabled_modules.get(
                "local_info", True):
            try:
                logger.info("Running Local Information Module (Module 2)")
                local_result = self.local_info_module.analyze(ip_obj)
                local_info = self._serialize_local_info(local_result)
                logger.info("Local information gathering completed")
            except Exception as e:
                error_msg = f"Local info module error: {e}"
                logger.error(error_msg, exc_info=True)
                errors.append(error_msg)
        elif not self.local_info_module:
            logger.warning("Local info module not available, skipping")
        else:
            logger.info("Local info module disabled by configuration")

        # Module 3: Internet Information
        internet_info = None
        should_run_internet = (
            "internet_info" in qualified_modules or
            self.config.force_internet
        )

        if should_run_internet and self.config.enabled_modules.get(
                "internet_info", True):
            if self.internet_info_module:
                try:
                    logger.info("Running Internet Information Module (Module 3)")
                    if self.config.force_internet:
                        logger.info("Internet module forced by configuration")
                    internet_info = self.internet_info_module.analyze(
                        ip_obj,
                        mode=self.config.reporting_mode
                    )
                    logger.info("Internet information gathering completed")
                except Exception as e:
                    error_msg = f"Internet info module error: {e}"
                    logger.error(error_msg, exc_info=True)
                    errors.append(error_msg)
            else:
                logger.warning("Internet info module not available, skipping")
        elif not should_run_internet:
            logger.info("Internet info module not qualified for this IP")
        else:
            logger.info("Internet info module disabled by configuration")

        # Module 4: Application Integration
        application_info = {}
        enabled_app_modules = self._get_enabled_application_modules()

        if enabled_app_modules and self.application_module:
            try:
                logger.info(
                    f"Running Application Module (Module 4) with submodules: {enabled_app_modules}")
                app_results = self.application_module.query_all_enabled(
                    ip_obj, enabled_app_modules)

                # Convert ApplicationResult objects to dictionaries
                for submodule_name, result in app_results.items():
                    application_info[submodule_name] = {
                        'success': result.success,
                        'data': result.data,
                        'error_message': result.error_message,
                        'source': result.source
                    }

                    # Collect errors from failed submodules
                    if not result.success and result.error_message:
                        error_msg = f"{submodule_name}: {result.error_message}"
                        logger.warning(error_msg)
                        errors.append(error_msg)
                    else:
                        logger.info(f"{submodule_name} query completed successfully")

            except Exception as e:
                error_msg = f"Application module error: {e}"
                logger.error(error_msg, exc_info=True)
                errors.append(error_msg)
        elif not self.application_module:
            logger.warning("Application module not available, skipping")
        elif not enabled_app_modules:
            logger.info("No application submodules enabled")

        # Create analysis result
        result = AnalysisResult(
            ip_address=ip_obj,
            scan_timestamp=start_time,
            classifications=classifications,
            local_info=local_info,
            internet_info=internet_info,
            application_info=application_info,
            errors=errors
        )

        # Store in database if configured
        if self.database_manager:
            try:
                self.database_manager.store_scan_result(result)
                logger.info("Scan result stored in database")
            except Exception as e:
                error_msg = f"Database storage error: {e}"
                logger.error(error_msg, exc_info=True)
                result.errors.append(error_msg)

        duration = (datetime.now() - start_time).total_seconds()
        logger.info("=" * 80)
        logger.info(f"Analysis completed in {duration:.2f} seconds")
        if errors:
            logger.warning(f"Analysis completed with {len(errors)} error(s)")
        else:
            logger.info("Analysis completed successfully")
        logger.info("=" * 80)

        return result

    def _get_enabled_application_modules(self) -> List[str]:
        """
        Get list of enabled application submodules from configuration.

        Returns:
            List of enabled submodule names
        """
        enabled = []
        app_submodules = ['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']

        for submodule in app_submodules:
            if self.config.enabled_modules.get(submodule, False):
                enabled.append(submodule)

        return enabled

    def _serialize_local_info(self, local_result) -> Dict[str, Any]:
        """
        Serialize LocalInfoResult to dictionary format.

        Args:
            local_result: LocalInfoResult object

        Returns:
            Dictionary representation
        """
        return {
            'is_local_subnet': local_result.is_local_subnet,
            'reachable': local_result.reachable,
            'mac_address': {
                'address': local_result.mac_address.address,
                'vendor': local_result.mac_address.vendor,
                'is_gateway': local_result.mac_address.is_gateway
            } if local_result.mac_address else None,
            'nmap_results': {
                'host_up': local_result.nmap_results.host_up,
                'os_detection': local_result.nmap_results.os_detection,
                'open_ports': local_result.nmap_results.open_ports,
                'services': local_result.nmap_results.services
            },
            'ssl_results': [
                {
                    'port': ssl.port,
                    'protocol': ssl.protocol,
                    'certificate': ssl.certificate,
                    'cipher_suites': ssl.cipher_suites,
                    'vulnerabilities': ssl.vulnerabilities
                }
                for ssl in local_result.ssl_results
            ],
            'traceroute_results': [
                {
                    'method': tr.method,
                    'hops': tr.hops,
                    'success': tr.success,
                    'error': tr.error
                }
                for tr in local_result.traceroute_results
            ],
            'reverse_dns': local_result.reverse_dns,
            'nat_detection': local_result.nat_detection
        }

    def validate_module_availability(self, module_names: List[str]) -> Dict[str, bool]:
        """
        Validate availability of requested modules.

        Args:
            module_names: List of module names to validate

        Returns:
            Dictionary mapping module names to availability status
        """
        availability = {}

        # Core modules availability depends on initialization
        core_modules = {
            'classification': self.classification_module is not None,
            'local_info': self.local_info_module is not None,
            'internet_info': self.internet_info_module is not None
        }

        for module in module_names:
            if module in core_modules:
                availability[module] = core_modules[module]
                logger.debug(f"Module {module} availability: {availability[module]}")

        # Application submodules need to be checked
        app_submodules = ['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']
        for module in module_names:
            if module in app_submodules:
                if not self.application_module:
                    availability[module] = False
                    logger.debug(
                        f"Module {module} not available (application module not initialized)")
                else:
                    try:
                        # Check if submodule can be loaded
                        submodule = self.application_module.load_submodule(module)
                        availability[module] = submodule is not None
                        logger.debug(
                            f"Module {module} availability: {
                                availability[module]}")
                    except Exception as e:
                        logger.warning(f"Module {module} not available: {e}")
                        availability[module] = False
            elif module not in core_modules:
                # Unknown/invalid module
                availability[module] = False
                logger.warning(f"Unknown module requested: {module}")

        return availability

    def get_available_modules(self) -> List[str]:
        """
        Get list of all available modules.

        Returns:
            List of available module names
        """
        available = []

        # Add available core modules
        if self.classification_module:
            available.append('classification')
        if self.local_info_module:
            available.append('local_info')
        if self.internet_info_module:
            available.append('internet_info')

        # Add available application submodules
        if self.application_module:
            try:
                app_submodules = self.application_module.get_available_submodules()
                available.extend(app_submodules)
            except Exception as e:
                logger.warning(f"Failed to get application submodules: {e}")

        logger.debug(f"Available modules: {available}")
        return available

    def cleanup(self):
        """
        Perform cleanup of resources.

        This method ensures proper cleanup of database connections,
        network sessions, and other resources.
        """
        logger.info("Performing cleanup")

        try:
            if self.database_manager:
                # Database manager uses context managers, no explicit cleanup needed
                logger.debug("Database resources cleaned up")
        except Exception as e:
            logger.error(f"Error during database cleanup: {e}")

        try:
            if self.application_module:
                # Close any open sessions in application module
                for submodule in self.application_module.loaded_submodules.values():
                    if hasattr(submodule, 'session'):
                        submodule.session.close()
                logger.debug("Application module sessions closed")
        except Exception as e:
            logger.error(f"Error during application module cleanup: {e}")

        logger.info("Cleanup completed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()
        return False
