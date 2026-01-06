"""
Application Integration Module (Module 4) for enterprise application queries.
"""

import importlib
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

# Type alias for IP addresses
IPAddress = Union[IPv4Address, IPv6Address]

logger = logging.getLogger(__name__)


@dataclass
class ApplicationResult:
    """Standardized result format for application submodules."""
    success: bool
    data: Dict[str, Any]
    error_message: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None


@dataclass
class AuthenticationConfig:
    """Configuration for application authentication."""
    auth_type: str  # 'api_key', 'basic', 'token', 'oauth'
    credentials: Dict[str, str]
    base_url: str
    timeout: int = 30


class CredentialManager:
    """Manages application credentials and authentication configuration."""
    
    DEFAULT_CREDENTIAL_PATH = "config/app_credentials.json"
    
    def __init__(self, credential_file: Optional[str] = None):
        """
        Initialize credential manager.
        
        Args:
            credential_file: Path to credential configuration file
        """
        self.credential_file = credential_file or self.DEFAULT_CREDENTIAL_PATH
        self._credentials: Dict[str, Dict] = {}
        self._load_credentials()
    
    def _load_credentials(self) -> None:
        """Load credentials from configuration file."""
        credential_path = Path(self.credential_file)
        
        if not credential_path.exists():
            logger.warning(f"Credential file not found: {self.credential_file}")
            logger.info(f"Create credentials by copying config/app_credentials.example.json to {self.credential_file}")
            return
        
        try:
            with open(credential_path, 'r', encoding='utf-8') as f:
                self._credentials = json.load(f)
            logger.info(f"Loaded credentials from {self.credential_file}")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load credentials from {self.credential_file}: {e}")
            self._credentials = {}
    
    def get_submodule_config(self, submodule_name: str) -> Optional[AuthenticationConfig]:
        """
        Get authentication configuration for a specific submodule.
        
        Args:
            submodule_name: Name of the submodule
            
        Returns:
            AuthenticationConfig object or None if not configured
        """
        submodule_config = self._credentials.get(submodule_name)
        
        if not submodule_config:
            logger.warning(f"No configuration found for submodule: {submodule_name}")
            return None
        
        if not submodule_config.get('enabled', False):
            logger.info(f"Submodule {submodule_name} is disabled in configuration")
            return None
        
        auth_config = submodule_config.get('authentication', {})
        if not auth_config:
            logger.warning(f"No authentication configuration for submodule: {submodule_name}")
            return None
        
        # Map authentication method to internal format
        method_mapping = {
            'api_token': 'api_key',
            'basic_auth': 'basic',
            'custom_headers': 'token'
        }
        
        auth_method = auth_config.get('method', '')
        mapped_method = method_mapping.get(auth_method, auth_method)
        
        # Extract credentials based on method
        credentials = {}
        if mapped_method == 'api_key':
            credentials['api_key'] = auth_config.get('api_token', '')
        elif mapped_method == 'basic':
            credentials['username'] = auth_config.get('username', '')
            credentials['password'] = auth_config.get('password', '')
        elif mapped_method == 'token':
            credentials['token'] = auth_config.get('api_token', '')
        
        return AuthenticationConfig(
            auth_type=mapped_method,
            credentials=credentials,
            base_url=submodule_config.get('base_url', ''),
            timeout=submodule_config.get('timeout', 30)
        )
    
    def validate_credentials(self) -> Dict[str, bool]:
        """
        Validate that all enabled submodules have proper credentials.
        
        Returns:
            Dictionary mapping submodule names to validation status
        """
        validation_results = {}
        
        for submodule_name, config in self._credentials.items():
            if submodule_name.startswith('_'):  # Skip metadata fields
                continue
                
            if not config.get('enabled', False):
                validation_results[submodule_name] = True  # Disabled is valid
                continue
            
            # Check required fields
            required_fields = ['base_url', 'authentication']
            missing_fields = [field for field in required_fields if not config.get(field)]
            
            if missing_fields:
                validation_results[submodule_name] = False
                logger.error(f"Missing required fields for {submodule_name}: {missing_fields}")
                continue
            
            # Check authentication configuration
            auth_config = config.get('authentication', {})
            auth_method = auth_config.get('method', '')
            
            if auth_method == 'api_token':
                validation_results[submodule_name] = bool(auth_config.get('api_token'))
            elif auth_method == 'basic_auth':
                validation_results[submodule_name] = bool(
                    auth_config.get('username') and auth_config.get('password')
                )
            elif auth_method == 'custom_headers':
                validation_results[submodule_name] = bool(auth_config.get('headers'))
            else:
                validation_results[submodule_name] = False
                logger.error(f"Unknown authentication method for {submodule_name}: {auth_method}")
        
        return validation_results
    
    def get_enabled_submodules(self) -> List[str]:
        """
        Get list of enabled submodule names.
        
        Returns:
            List of enabled submodule names
        """
        enabled = []
        for submodule_name, config in self._credentials.items():
            if submodule_name.startswith('_'):  # Skip metadata fields
                continue
            if config.get('enabled', False):
                enabled.append(submodule_name)
        return enabled


class ApplicationError(Exception):
    """Base exception for application integration errors."""
    pass


class AuthenticationError(ApplicationError):
    """Exception raised for authentication failures."""
    pass


class ConnectionError(ApplicationError):
    """Exception raised for connection failures."""
    pass


class ApplicationSubmodule(ABC):
    """Abstract base class for application integration submodules."""

    def __init__(self, config: Optional[AuthenticationConfig] = None):
        """Initialize the submodule with configuration."""
        self.config = config
        self.session = requests.Session()
        if config:
            self._setup_authentication()

    def _setup_authentication(self):
        """Setup authentication for the session."""
        if not self.config:
            return

        auth_type = self.config.auth_type
        credentials = self.config.credentials

        if auth_type == 'api_key':
            # Add API key to headers
            api_key = credentials.get('api_key', '')
            self.session.headers.update({
                'Authorization': f"Token {api_key}"
            })
        elif auth_type == 'basic':
            # Setup basic authentication
            from requests.auth import HTTPBasicAuth
            self.session.auth = HTTPBasicAuth(
                credentials.get('username', ''),
                credentials.get('password', '')
            )
        elif auth_type == 'token':
            # Add bearer token
            token = credentials.get('token', '')
            self.session.headers.update({
                'Authorization': f"Bearer {token}"
            })
        elif auth_type == 'oauth':
            # OAuth implementation would go here
            pass

        # Add any custom headers from configuration
        if hasattr(self.config, 'headers') and self.config.headers:
            self.session.headers.update(self.config.headers)

    @abstractmethod
    def query_ip(self, ip: IPAddress) -> ApplicationResult:
        """
        Query the application for IP-related information.
        
        Args:
            ip: IPAddress object to query
            
        Returns:
            ApplicationResult with standardized format
        """
        pass

    def _make_request(self, endpoint: str, method: str = 'GET', **kwargs) -> Dict:
        """
        Make an authenticated request to the application API.
        
        Args:
            endpoint: API endpoint to call
            method: HTTP method to use
            **kwargs: Additional arguments for requests
            
        Returns:
            Response data as dictionary
            
        Raises:
            AuthenticationError: If authentication fails
            ConnectionError: If connection fails
            ApplicationError: For other API errors
        """
        if not self.config:
            raise ApplicationError("No configuration provided for API access")

        url = f"{self.config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.config.timeout,
                **kwargs
            )
            
            if response.status_code == 401:
                raise AuthenticationError("Authentication failed - invalid credentials")
            elif response.status_code == 403:
                raise AuthenticationError("Authentication failed - insufficient permissions")
            elif response.status_code >= 400:
                raise ApplicationError(f"API error: {response.status_code} - {response.text}")
                
            return response.json() if response.content else {}
            
        except Timeout:
            raise ConnectionError(f"Request timeout after {self.config.timeout} seconds")
        except RequestException as e:
            raise ConnectionError(f"Connection error: {str(e)}")


class NetBoxSubmodule(ApplicationSubmodule):
    """NetBox IPAM system integration submodule."""

    def query_ip(self, ip: IPAddress) -> ApplicationResult:
        """Query NetBox for IP address information."""
        try:
            # Query IP address details
            ip_data = self._make_request(f"api/ipam/ip-addresses/?address={ip}")
            
            # Query prefix information
            prefix_data = self._make_request(f"api/ipam/prefixes/?contains={ip}")
            
            result_data = {
                'ip_addresses': ip_data.get('results', []),
                'prefixes': prefix_data.get('results', []),
                'source': 'NetBox IPAM'
            }
            
            return ApplicationResult(
                success=True,
                data=result_data,
                source='netbox'
            )
            
        except (AuthenticationError, ConnectionError, ApplicationError) as e:
            return ApplicationResult(
                success=False,
                data={},
                error_message=str(e),
                source='netbox'
            )


class CheckMKSubmodule(ApplicationSubmodule):
    """CheckMK monitoring system integration submodule."""

    def query_ip(self, ip: IPAddress) -> ApplicationResult:
        """Query CheckMK for monitoring information."""
        try:
            # Query hosts by IP address
            hosts_data = self._make_request(f"check_mk/api/1.0/objects/host_config", 
                                          params={'effective_attributes': 'true'})
            
            # Filter hosts by IP address
            matching_hosts = []
            for host in hosts_data.get('value', {}).values():
                if host.get('attributes', {}).get('ipaddress') == str(ip):
                    matching_hosts.append(host)
            
            result_data = {
                'hosts': matching_hosts,
                'source': 'CheckMK Monitoring'
            }
            
            return ApplicationResult(
                success=True,
                data=result_data,
                source='checkmk'
            )
            
        except (AuthenticationError, ConnectionError, ApplicationError) as e:
            return ApplicationResult(
                success=False,
                data={},
                error_message=str(e),
                source='checkmk'
            )


class OpenITCockpitSubmodule(ApplicationSubmodule):
    """OpenITCockpit IT management integration submodule."""

    def query_ip(self, ip: IPAddress) -> ApplicationResult:
        """Query OpenITCockpit for IT management information."""
        try:
            # Query hosts by IP address
            hosts_data = self._make_request(f"hosts/index.json", 
                                          params={'filter[Hosts.address]': str(ip)})
            
            result_data = {
                'hosts': hosts_data.get('hosts', []),
                'source': 'OpenITCockpit'
            }
            
            return ApplicationResult(
                success=True,
                data=result_data,
                source='openitcockpit'
            )
            
        except (AuthenticationError, ConnectionError, ApplicationError) as e:
            return ApplicationResult(
                success=False,
                data={},
                error_message=str(e),
                source='openitcockpit'
            )


class OpenVASSubmodule(ApplicationSubmodule):
    """OpenVAS vulnerability assessment integration submodule."""

    def query_ip(self, ip: IPAddress) -> ApplicationResult:
        """Query OpenVAS for vulnerability assessment information."""
        try:
            # Query targets and reports for the IP
            targets_data = self._make_request(f"targets", 
                                            params={'filter': f'hosts={ip}'})
            
            result_data = {
                'targets': targets_data.get('targets', []),
                'source': 'OpenVAS Vulnerability Scanner'
            }
            
            return ApplicationResult(
                success=True,
                data=result_data,
                source='openvas'
            )
            
        except (AuthenticationError, ConnectionError, ApplicationError) as e:
            return ApplicationResult(
                success=False,
                data={},
                error_message=str(e),
                source='openvas'
            )


class InfobloxSubmodule(ApplicationSubmodule):
    """Infoblox DNS/DHCP system integration submodule."""

    def query_ip(self, ip: IPAddress) -> ApplicationResult:
        """Query Infoblox for DNS/DHCP information."""
        try:
            # Query IP address records
            ip_data = self._make_request(f"wapi/v2.10/ipv4address", 
                                       params={'ip_address': str(ip)})
            
            # Query DNS records
            dns_data = self._make_request(f"wapi/v2.10/record:a", 
                                        params={'ipv4addr': str(ip)})
            
            result_data = {
                'ip_records': ip_data,
                'dns_records': dns_data,
                'source': 'Infoblox DNS/DHCP'
            }
            
            return ApplicationResult(
                success=True,
                data=result_data,
                source='infoblox'
            )
            
        except (AuthenticationError, ConnectionError, ApplicationError) as e:
            return ApplicationResult(
                success=False,
                data={},
                error_message=str(e),
                source='infoblox'
            )


class ApplicationModule:
    """Module for interfacing with enterprise applications."""

    # Available submodules
    AVAILABLE_SUBMODULES = {
        'netbox': NetBoxSubmodule,
        'checkmk': CheckMKSubmodule,
        'openitcockpit': OpenITCockpitSubmodule,
        'openvas': OpenVASSubmodule,
        'infoblox': InfobloxSubmodule
    }

    def __init__(self, credential_file_or_configurations=None, configurations: Optional[Dict[str, AuthenticationConfig]] = None):
        """
        Initialize the application module.
        
        Args:
            credential_file_or_configurations: Either a path to credential configuration file (str) 
                                             or a dictionary of configurations (for backward compatibility)
            configurations: Dictionary mapping submodule names to their configurations (deprecated, use first arg)
        """
        # Handle backward compatibility
        if isinstance(credential_file_or_configurations, dict):
            # Old style: ApplicationModule({submodule: config})
            self.credential_manager = None
            self.configurations = credential_file_or_configurations
        elif configurations is not None:
            # Old style: ApplicationModule(credential_file, configurations)
            self.credential_manager = None
            self.configurations = configurations
        else:
            # New style: ApplicationModule(credential_file)
            self.credential_manager = CredentialManager(credential_file_or_configurations)
            self.configurations = {}
        
        self.loaded_submodules: Dict[str, ApplicationSubmodule] = {}

    def load_submodule(self, name: str) -> Optional[ApplicationSubmodule]:
        """
        Load and return a specific submodule.

        Args:
            name: Name of the submodule to load

        Returns:
            ApplicationSubmodule instance or None if not available
            
        Raises:
            ApplicationError: If submodule cannot be loaded
        """
        if name not in self.AVAILABLE_SUBMODULES:
            available = ', '.join(self.AVAILABLE_SUBMODULES.keys())
            raise ApplicationError(f"Unknown submodule '{name}'. Available: {available}")

        if name in self.loaded_submodules:
            return self.loaded_submodules[name]

        try:
            submodule_class = self.AVAILABLE_SUBMODULES[name]
            
            # Get configuration from either credential manager or direct configurations
            if self.credential_manager:
                config = self.credential_manager.get_submodule_config(name)
            else:
                config = self.configurations.get(name)
            
            if not config:
                logger.warning(f"No valid configuration provided for submodule '{name}'")
                # Create submodule without configuration for testing
                submodule = submodule_class()
            else:
                submodule = submodule_class(config)
            
            self.loaded_submodules[name] = submodule
            return submodule
            
        except Exception as e:
            raise ApplicationError(f"Failed to load submodule '{name}': {str(e)}")

    def query_all_enabled(self, ip: IPAddress, enabled_submodules: Optional[List[str]] = None) -> Dict[str, ApplicationResult]:
        """
        Query all enabled submodules for IP information.

        Args:
            ip: IPAddress object to query
            enabled_submodules: List of submodule names to query (if None, uses configured enabled submodules)

        Returns:
            Dictionary mapping submodule names to their results
        """
        if enabled_submodules is None:
            if self.credential_manager:
                enabled_submodules = self.credential_manager.get_enabled_submodules()
            else:
                # For backward compatibility, use all configured submodules
                enabled_submodules = list(self.configurations.keys())
        
        results = {}
        
        for submodule_name in enabled_submodules:
            try:
                submodule = self.load_submodule(submodule_name)
                if submodule:
                    logger.info(f"Querying {submodule_name} for IP {ip}")
                    result = submodule.query_ip(ip)
                    results[submodule_name] = result
                else:
                    results[submodule_name] = ApplicationResult(
                        success=False,
                        data={},
                        error_message=f"Submodule '{submodule_name}' not available",
                        source=submodule_name
                    )
            except Exception as e:
                logger.error(f"Error querying {submodule_name}: {str(e)}")
                results[submodule_name] = ApplicationResult(
                    success=False,
                    data={},
                    error_message=str(e),
                    source=submodule_name
                )
        
        return results

    def get_available_submodules(self) -> List[str]:
        """
        Get list of available submodule names.
        
        Returns:
            List of available submodule names
        """
        return list(self.AVAILABLE_SUBMODULES.keys())

    def get_enabled_submodules(self) -> List[str]:
        """
        Get list of enabled submodule names from configuration.
        
        Returns:
            List of enabled submodule names
        """
        if self.credential_manager:
            return self.credential_manager.get_enabled_submodules()
        else:
            # For backward compatibility, return all configured submodules
            return list(self.configurations.keys())

    def validate_submodule_availability(self, submodule_names: List[str]) -> Dict[str, bool]:
        """
        Validate availability of requested submodules.
        
        Args:
            submodule_names: List of submodule names to validate
            
        Returns:
            Dictionary mapping submodule names to availability status
        """
        availability = {}
        
        for name in submodule_names:
            try:
                submodule = self.load_submodule(name)
                availability[name] = submodule is not None
            except ApplicationError:
                availability[name] = False
                
        return availability

    def validate_credentials(self) -> Dict[str, bool]:
        """
        Validate credentials for all configured submodules.
        
        Returns:
            Dictionary mapping submodule names to credential validation status
        """
        if self.credential_manager:
            return self.credential_manager.validate_credentials()
        else:
            # For backward compatibility, assume all configured submodules are valid
            return {name: True for name in self.configurations.keys()}

    def set_credential_file(self, credential_file: str) -> None:
        """
        Set a new credential file and reload credentials.
        
        Args:
            credential_file: Path to new credential configuration file
        """
        self.credential_manager = CredentialManager(credential_file)
        self.configurations = {}  # Clear old configurations
        # Clear loaded submodules to force reload with new credentials
        self.loaded_submodules.clear()
