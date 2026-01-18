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
    verify_ssl: bool = True


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
            timeout=submodule_config.get('timeout', 30),
            verify_ssl=submodule_config.get('verify_ssl', True)
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
        
        # Set verify parameter based on configuration
        if 'verify' not in kwargs:
            kwargs['verify'] = self.config.verify_ssl
        
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
        """
        Query NetBox for comprehensive IP address information.
        
        Retrieves:
        - IP address details with network information
        - Prefix and subnet information
        - Device and interface associations
        - VLAN and VRF information
        
        Args:
            ip: IPAddress object to query
            
        Returns:
            ApplicationResult with comprehensive IPAM data
        """
        try:
            result_data = {
                'ip_addresses': [],
                'prefixes': [],
                'devices': [],
                'interfaces': [],
                'vlans': [],
                'vrfs': [],
                'source': 'NetBox IPAM'
            }
            
            # Query IP address details
            logger.info(f"Querying NetBox for IP address: {ip}")
            ip_data = self._make_request(f"api/ipam/ip-addresses/?address={ip}")
            ip_results = ip_data.get('results', [])
            result_data['ip_addresses'] = ip_results
            
            # Query prefix information (subnets containing this IP)
            logger.info(f"Querying NetBox for prefixes containing: {ip}")
            prefix_data = self._make_request(f"api/ipam/prefixes/?contains={ip}")
            result_data['prefixes'] = prefix_data.get('results', [])
            
            # If we found IP address records, get associated device and interface information
            if ip_results:
                for ip_record in ip_results:
                    # Get interface association
                    assigned_object = ip_record.get('assigned_object')
                    if assigned_object:
                        assigned_object_id = assigned_object.get('id')
                        assigned_object_type = assigned_object.get('object_type', '')
                        
                        # Query interface details if assigned to an interface
                        if 'interface' in assigned_object_type.lower() and assigned_object_id:
                            try:
                                logger.info(f"Querying NetBox for interface: {assigned_object_id}")
                                interface_data = self._make_request(f"api/dcim/interfaces/{assigned_object_id}/")
                                result_data['interfaces'].append(interface_data)
                                
                                # Get device information from interface
                                device_info = interface_data.get('device')
                                if device_info and device_info.get('id'):
                                    device_id = device_info['id']
                                    logger.info(f"Querying NetBox for device: {device_id}")
                                    device_data = self._make_request(f"api/dcim/devices/{device_id}/")
                                    result_data['devices'].append(device_data)
                            except (AuthenticationError, ConnectionError, ApplicationError) as e:
                                logger.warning(f"Failed to query interface/device details: {e}")
                    
                    # Get VRF information if present
                    vrf = ip_record.get('vrf')
                    if vrf and vrf.get('id'):
                        vrf_id = vrf['id']
                        try:
                            logger.info(f"Querying NetBox for VRF: {vrf_id}")
                            vrf_data = self._make_request(f"api/ipam/vrfs/{vrf_id}/")
                            result_data['vrfs'].append(vrf_data)
                        except (AuthenticationError, ConnectionError, ApplicationError) as e:
                            logger.warning(f"Failed to query VRF details: {e}")
            
            # Get VLAN information from prefixes
            for prefix in result_data['prefixes']:
                vlan = prefix.get('vlan')
                if vlan and vlan.get('id'):
                    vlan_id = vlan['id']
                    try:
                        logger.info(f"Querying NetBox for VLAN: {vlan_id}")
                        vlan_data = self._make_request(f"api/ipam/vlans/{vlan_id}/")
                        # Avoid duplicates
                        if not any(v.get('id') == vlan_id for v in result_data['vlans']):
                            result_data['vlans'].append(vlan_data)
                    except (AuthenticationError, ConnectionError, ApplicationError) as e:
                        logger.warning(f"Failed to query VLAN details: {e}")
            
            # Determine success based on whether we found any data
            has_data = any([
                result_data['ip_addresses'],
                result_data['prefixes'],
                result_data['devices'],
                result_data['interfaces'],
                result_data['vlans'],
                result_data['vrfs']
            ])
            
            return ApplicationResult(
                success=True,
                data=result_data,
                source='netbox'
            )
            
        except AuthenticationError as e:
            logger.error(f"NetBox authentication error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Authentication failed: {str(e)}",
                source='netbox'
            )
        except ConnectionError as e:
            logger.error(f"NetBox connection error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Connection failed: {str(e)}",
                source='netbox'
            )
        except ApplicationError as e:
            logger.error(f"NetBox API error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"API error: {str(e)}",
                source='netbox'
            )
        except Exception as e:
            logger.error(f"Unexpected error querying NetBox: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Unexpected error: {str(e)}",
                source='netbox'
            )


class CheckMKSubmodule(ApplicationSubmodule):
    """CheckMK monitoring system integration submodule."""

    def query_ip(self, ip: IPAddress) -> ApplicationResult:
        """
        Query CheckMK for comprehensive monitoring information.
        
        Retrieves:
        - Host information by IP address
        - Service status and performance data
        - Alert and notification history
        - Monitoring configuration and check results
        
        Args:
            ip: IPAddress object to query
            
        Returns:
            ApplicationResult with comprehensive monitoring data
        """
        try:
            result_data = {
                'hosts': [],
                'services': [],
                'host_status': [],
                'alerts': [],
                'notifications': [],
                'performance_data': [],
                'check_results': [],
                'source': 'CheckMK Monitoring'
            }
            
            # Query all hosts to find matching IP
            logger.info(f"Querying CheckMK for hosts with IP: {ip}")
            try:
                hosts_response = self._make_request(
                    "check_mk/api/1.0/domain-types/host_config/collections/all"
                )
                
                # Filter hosts by IP address
                all_hosts = hosts_response.get('value', [])
                matching_hosts = []
                host_names = []
                
                for host in all_hosts:
                    host_attrs = host.get('extensions', {}).get('attributes', {})
                    if host_attrs.get('ipaddress') == str(ip):
                        matching_hosts.append(host)
                        host_names.append(host.get('id', ''))
                
                result_data['hosts'] = matching_hosts
                
                # If we found matching hosts, query additional information
                if host_names:
                    for host_name in host_names:
                        # Query host status
                        logger.info(f"Querying CheckMK for host status: {host_name}")
                        try:
                            status_response = self._make_request(
                                f"check_mk/api/1.0/objects/host/{host_name}"
                            )
                            result_data['host_status'].append(status_response)
                        except (AuthenticationError, ConnectionError, ApplicationError) as e:
                            logger.warning(f"Failed to query host status for {host_name}: {e}")
                        
                        # Query services for this host
                        logger.info(f"Querying CheckMK for services on host: {host_name}")
                        try:
                            services_response = self._make_request(
                                "check_mk/api/1.0/domain-types/service/collections/all",
                                params={'host_name': host_name}
                            )
                            services = services_response.get('value', [])
                            result_data['services'].extend(services)
                            
                            # Extract performance data from services
                            for service in services:
                                service_extensions = service.get('extensions', {})
                                metrics = service_extensions.get('metrics', {})
                                if metrics:
                                    result_data['performance_data'].append({
                                        'host': host_name,
                                        'service': service.get('id', ''),
                                        'metrics': metrics
                                    })
                                
                                # Extract check results
                                check_result = service_extensions.get('check_result', {})
                                if check_result:
                                    result_data['check_results'].append({
                                        'host': host_name,
                                        'service': service.get('id', ''),
                                        'result': check_result
                                    })
                        except (AuthenticationError, ConnectionError, ApplicationError) as e:
                            logger.warning(f"Failed to query services for {host_name}: {e}")
                        
                        # Query alerts/notifications for this host
                        logger.info(f"Querying CheckMK for notifications on host: {host_name}")
                        try:
                            # Try to get recent notifications
                            notifications_response = self._make_request(
                                "check_mk/api/1.0/domain-types/notification/collections/all",
                                params={'host_name': host_name}
                            )
                            notifications = notifications_response.get('value', [])
                            result_data['notifications'].extend(notifications)
                        except (AuthenticationError, ConnectionError, ApplicationError) as e:
                            logger.warning(f"Failed to query notifications for {host_name}: {e}")
                        
                        # Query alert history
                        logger.info(f"Querying CheckMK for alert history on host: {host_name}")
                        try:
                            alerts_response = self._make_request(
                                "check_mk/api/1.0/domain-types/event/collections/all",
                                params={'host_name': host_name}
                            )
                            alerts = alerts_response.get('value', [])
                            result_data['alerts'].extend(alerts)
                        except (AuthenticationError, ConnectionError, ApplicationError) as e:
                            logger.warning(f"Failed to query alerts for {host_name}: {e}")
                
            except (AuthenticationError, ConnectionError, ApplicationError) as e:
                logger.error(f"Failed to query CheckMK hosts: {e}")
                raise
            
            # Determine success based on whether we found any data
            has_data = any([
                result_data['hosts'],
                result_data['services'],
                result_data['host_status'],
                result_data['alerts'],
                result_data['notifications'],
                result_data['performance_data'],
                result_data['check_results']
            ])
            
            return ApplicationResult(
                success=True,
                data=result_data,
                source='checkmk'
            )
            
        except AuthenticationError as e:
            logger.error(f"CheckMK authentication error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Authentication failed: {str(e)}",
                source='checkmk'
            )
        except ConnectionError as e:
            logger.error(f"CheckMK connection error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Connection failed: {str(e)}",
                source='checkmk'
            )
        except ApplicationError as e:
            logger.error(f"CheckMK API error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"API error: {str(e)}",
                source='checkmk'
            )
        except Exception as e:
            logger.error(f"Unexpected error querying CheckMK: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Unexpected error: {str(e)}",
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
        """
        Query OpenVAS for comprehensive vulnerability assessment information.
        
        Retrieves:
        - Target and scan result retrieval by IP address
        - Vulnerability reports and severity information
        - Scan history and configuration queries
        - Threat intelligence and CVE information
        
        Args:
            ip: IPAddress object to query
            
        Returns:
            ApplicationResult with comprehensive vulnerability assessment data
        """
        try:
            result_data = {
                'targets': [],
                'tasks': [],
                'reports': [],
                'results': [],
                'vulnerabilities': [],
                'cve_information': [],
                'scan_history': [],
                'severity_summary': {},
                'source': 'OpenVAS Vulnerability Scanner'
            }
            
            # Query targets containing this IP address
            logger.info(f"Querying OpenVAS for targets with IP: {ip}")
            try:
                targets_response = self._make_request(
                    "api/v1/targets",
                    params={'filter': f'hosts~{ip}'}
                )
                targets = targets_response.get('data', []) if isinstance(targets_response, dict) else []
                result_data['targets'] = targets
                
                # For each target, get associated tasks and reports
                for target in targets:
                    target_id = target.get('id', '')
                    if not target_id:
                        continue
                    
                    # Query tasks for this target
                    logger.info(f"Querying OpenVAS for tasks on target: {target_id}")
                    try:
                        tasks_response = self._make_request(
                            "api/v1/tasks",
                            params={'filter': f'target_id={target_id}'}
                        )
                        tasks = tasks_response.get('data', []) if isinstance(tasks_response, dict) else []
                        result_data['tasks'].extend(tasks)
                        
                        # For each task, get reports and results
                        for task in tasks:
                            task_id = task.get('id', '')
                            if not task_id:
                                continue
                            
                            # Query reports for this task
                            logger.info(f"Querying OpenVAS for reports on task: {task_id}")
                            try:
                                reports_response = self._make_request(
                                    "api/v1/reports",
                                    params={'filter': f'task_id={task_id}'}
                                )
                                reports = reports_response.get('data', []) if isinstance(reports_response, dict) else []
                                result_data['reports'].extend(reports)
                                
                                # For each report, get detailed results
                                for report in reports:
                                    report_id = report.get('id', '')
                                    if not report_id:
                                        continue
                                    
                                    # Query results for this report
                                    logger.info(f"Querying OpenVAS for results in report: {report_id}")
                                    try:
                                        results_response = self._make_request(
                                            f"api/v1/reports/{report_id}/results",
                                            params={'filter': f'host={ip}'}
                                        )
                                        results = results_response.get('data', []) if isinstance(results_response, dict) else []
                                        result_data['results'].extend(results)
                                        
                                        # Extract vulnerability and CVE information from results
                                        for result in results:
                                            # Extract vulnerability details
                                            vulnerability = {
                                                'name': result.get('name', ''),
                                                'severity': result.get('severity', 0),
                                                'threat': result.get('threat', ''),
                                                'description': result.get('description', ''),
                                                'solution': result.get('solution', ''),
                                                'port': result.get('port', ''),
                                                'host': result.get('host', ''),
                                                'nvt_oid': result.get('nvt', {}).get('oid', ''),
                                                'cvss_base': result.get('nvt', {}).get('cvss_base', ''),
                                                'report_id': report_id,
                                                'task_id': task_id
                                            }
                                            result_data['vulnerabilities'].append(vulnerability)
                                            
                                            # Extract CVE references
                                            nvt = result.get('nvt', {})
                                            refs = nvt.get('refs', {})
                                            cve_refs = refs.get('ref', []) if isinstance(refs.get('ref'), list) else [refs.get('ref', {})]
                                            
                                            for ref in cve_refs:
                                                if isinstance(ref, dict) and ref.get('type') == 'cve':
                                                    cve_info = {
                                                        'cve_id': ref.get('id', ''),
                                                        'vulnerability_name': result.get('name', ''),
                                                        'severity': result.get('severity', 0),
                                                        'host': result.get('host', ''),
                                                        'port': result.get('port', '')
                                                    }
                                                    result_data['cve_information'].append(cve_info)
                                    
                                    except (AuthenticationError, ConnectionError, ApplicationError) as e:
                                        logger.warning(f"Failed to query results for report {report_id}: {e}")
                            
                            except (AuthenticationError, ConnectionError, ApplicationError) as e:
                                logger.warning(f"Failed to query reports for task {task_id}: {e}")
                    
                    except (AuthenticationError, ConnectionError, ApplicationError) as e:
                        logger.warning(f"Failed to query tasks for target {target_id}: {e}")
            
            except (AuthenticationError, ConnectionError, ApplicationError) as e:
                logger.error(f"Failed to query OpenVAS targets: {e}")
                raise
            
            # Build scan history from tasks
            for task in result_data['tasks']:
                scan_entry = {
                    'task_id': task.get('id', ''),
                    'task_name': task.get('name', ''),
                    'status': task.get('status', ''),
                    'progress': task.get('progress', 0),
                    'last_report': task.get('last_report', {}),
                    'creation_time': task.get('creation_time', ''),
                    'modification_time': task.get('modification_time', '')
                }
                result_data['scan_history'].append(scan_entry)
            
            # Calculate severity summary
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'log': 0
            }
            
            for vuln in result_data['vulnerabilities']:
                severity = float(vuln.get('severity', 0))
                threat = vuln.get('threat', '').lower()
                
                if severity >= 9.0 or threat == 'critical':
                    severity_counts['critical'] += 1
                elif severity >= 7.0 or threat == 'high':
                    severity_counts['high'] += 1
                elif severity >= 4.0 or threat == 'medium':
                    severity_counts['medium'] += 1
                elif severity > 0.0 or threat == 'low':
                    severity_counts['low'] += 1
                else:
                    severity_counts['log'] += 1
            
            result_data['severity_summary'] = severity_counts
            
            # Determine success based on whether we found any data
            has_data = any([
                result_data['targets'],
                result_data['tasks'],
                result_data['reports'],
                result_data['results'],
                result_data['vulnerabilities'],
                result_data['cve_information']
            ])
            
            return ApplicationResult(
                success=True,
                data=result_data,
                source='openvas'
            )
            
        except AuthenticationError as e:
            logger.error(f"OpenVAS authentication error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Authentication failed: {str(e)}",
                source='openvas'
            )
        except ConnectionError as e:
            logger.error(f"OpenVAS connection error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Connection failed: {str(e)}",
                source='openvas'
            )
        except ApplicationError as e:
            logger.error(f"OpenVAS API error: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"API error: {str(e)}",
                source='openvas'
            )
        except Exception as e:
            logger.error(f"Unexpected error querying OpenVAS: {e}")
            return ApplicationResult(
                success=False,
                data={},
                error_message=f"Unexpected error: {str(e)}",
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
