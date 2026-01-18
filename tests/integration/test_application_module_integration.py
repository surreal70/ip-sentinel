"""
Integration tests for Application Module submodules.

Tests comprehensive integration of NetBox, CheckMK, and OpenVAS submodules including:
- Submodule interaction and data correlation
- Authentication and configuration management across submodules
- Error isolation and graceful degradation
- Standardized result formatting across all submodules
- Multiple submodules executing simultaneously
- Partial failure scenarios

Requirements: 9.1, 9.2, 9.3, 9.5, 9.7, 9.8
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from ipaddress import IPv4Address, IPv6Address
import json
import tempfile
import os
from pathlib import Path
from requests.exceptions import Timeout, RequestException

from src.ip_mana.modules.application import (
    ApplicationModule,
    ApplicationResult,
    AuthenticationConfig,
    CredentialManager,
    NetBoxSubmodule,
    CheckMKSubmodule,
    OpenVASSubmodule,
    AuthenticationError,
    ConnectionError as AppConnectionError,
    ApplicationError
)


class TestApplicationModuleIntegration(unittest.TestCase):
    """Integration tests for Application Module with multiple submodules."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_ips = [
            IPv4Address('192.168.143.55'),
            IPv4Address('192.168.143.1'),
            IPv4Address('192.168.141.15'),
            IPv4Address('80.152.228.15'),
            IPv4Address('167.235.220.72')
        ]
        
        # Create test configurations for all submodules
        self.netbox_config = AuthenticationConfig(
            auth_type='api_key',
            credentials={'api_key': 'netbox_test_token'},
            base_url='https://netbox.example.com',
            timeout=30
        )
        
        self.checkmk_config = AuthenticationConfig(
            auth_type='basic',
            credentials={'username': 'automation', 'password': 'test_pass'},
            base_url='https://checkmk.example.com/site/monitoring',
            timeout=30
        )
        
        self.openvas_config = AuthenticationConfig(
            auth_type='api_key',
            credentials={'api_key': 'openvas_test_token'},
            base_url='https://openvas.example.com',
            timeout=60
        )
        
        self.configurations = {
            'netbox': self.netbox_config,
            'checkmk': self.checkmk_config,
            'openvas': self.openvas_config
        }
    
    def test_application_module_initialization(self):
        """Test ApplicationModule initialization with multiple submodule configurations."""
        app_module = ApplicationModule(configurations=self.configurations)
        
        self.assertIsNotNone(app_module)
        self.assertEqual(len(app_module.configurations), 3)
        self.assertIn('netbox', app_module.configurations)
        self.assertIn('checkmk', app_module.configurations)
        self.assertIn('openvas', app_module.configurations)
    
    def test_load_all_submodules(self):
        """Test loading all implemented submodules."""
        app_module = ApplicationModule(configurations=self.configurations)
        
        # Load each submodule
        netbox = app_module.load_submodule('netbox')
        checkmk = app_module.load_submodule('checkmk')
        openvas = app_module.load_submodule('openvas')
        
        self.assertIsInstance(netbox, NetBoxSubmodule)
        self.assertIsInstance(checkmk, CheckMKSubmodule)
        self.assertIsInstance(openvas, OpenVASSubmodule)
        
        # Verify submodules are cached
        self.assertEqual(len(app_module.loaded_submodules), 3)
    
    def test_get_available_submodules(self):
        """Test retrieving list of available submodules."""
        app_module = ApplicationModule(configurations=self.configurations)
        
        available = app_module.get_available_submodules()
        
        self.assertIsInstance(available, list)
        self.assertIn('netbox', available)
        self.assertIn('checkmk', available)
        self.assertIn('openvas', available)
        self.assertIn('openitcockpit', available)
        self.assertIn('infoblox', available)
    
    def test_get_enabled_submodules(self):
        """Test retrieving list of enabled submodules from configuration."""
        app_module = ApplicationModule(configurations=self.configurations)
        
        enabled = app_module.get_enabled_submodules()
        
        self.assertIsInstance(enabled, list)
        self.assertEqual(len(enabled), 3)
        self.assertIn('netbox', enabled)
        self.assertIn('checkmk', enabled)
        self.assertIn('openvas', enabled)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_query_all_enabled_success(self, mock_request):
        """Test querying all enabled submodules successfully."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = self.test_ips[0]  # 192.168.143.55
        
        # Mock successful responses for all submodules
        def mock_response_factory(method, url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True
            
            if 'netbox' in url:
                response.json.return_value = {
                    'results': [{
                        'id': 1,
                        'address': str(test_ip),
                        'status': {'value': 'active'}
                    }]
                }
            elif 'checkmk' in url or 'check_mk' in url:
                response.json.return_value = {
                    'value': [{
                        'id': 'test-host',
                        'extensions': {
                            'attributes': {'ipaddress': str(test_ip)}
                        }
                    }]
                }
            elif 'openvas' in url:
                response.json.return_value = {
                    'data': [{
                        'id': 'target-001',
                        'hosts': str(test_ip)
                    }]
                }
            else:
                response.json.return_value = {'results': [], 'value': [], 'data': []}
            
            return response
        
        mock_request.side_effect = mock_response_factory
        
        results = app_module.query_all_enabled(test_ip)
        
        # Verify all submodules returned results
        self.assertEqual(len(results), 3)
        self.assertIn('netbox', results)
        self.assertIn('checkmk', results)
        self.assertIn('openvas', results)
        
        # Verify all results are successful
        for submodule_name, result in results.items():
            self.assertIsInstance(result, ApplicationResult)
            self.assertTrue(result.success, f"{submodule_name} should succeed")
            self.assertEqual(result.source, submodule_name)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_query_specific_submodules(self, mock_request):
        """Test querying only specific submodules."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = self.test_ips[1]  # 192.168.143.1
        
        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'results': []}
        mock_request.return_value = response
        
        # Query only NetBox and CheckMK
        results = app_module.query_all_enabled(test_ip, enabled_submodules=['netbox', 'checkmk'])
        
        self.assertEqual(len(results), 2)
        self.assertIn('netbox', results)
        self.assertIn('checkmk', results)
        self.assertNotIn('openvas', results)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_partial_failure_isolation(self, mock_request):
        """Test that failure in one submodule doesn't affect others (error isolation)."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = self.test_ips[2]  # 192.168.141.15
        
        call_count = {'count': 0}
        
        def mock_response_factory(method, url, **kwargs):
            call_count['count'] += 1
            response = Mock()
            response.content = True
            
            if 'netbox' in url:
                # NetBox succeeds
                response.status_code = 200
                response.json.return_value = {
                    'results': [{
                        'id': 1,
                        'address': str(test_ip)
                    }]
                }
            elif 'checkmk' in url or 'check_mk' in url:
                # CheckMK fails with authentication error
                response.status_code = 401
                response.text = 'Authentication failed'
            elif 'openvas' in url:
                # OpenVAS succeeds
                response.status_code = 200
                response.json.return_value = {
                    'data': [{
                        'id': 'target-001',
                        'hosts': str(test_ip)
                    }]
                }
            else:
                response.status_code = 200
                response.json.return_value = {'results': [], 'value': [], 'data': []}
            
            return response
        
        mock_request.side_effect = mock_response_factory
        
        results = app_module.query_all_enabled(test_ip)
        
        # Verify all submodules returned results
        self.assertEqual(len(results), 3)
        
        # NetBox should succeed
        self.assertTrue(results['netbox'].success)
        self.assertEqual(len(results['netbox'].data.get('ip_addresses', [])), 1)
        
        # CheckMK should fail but not crash
        self.assertFalse(results['checkmk'].success)
        self.assertIn('Authentication failed', results['checkmk'].error_message)
        
        # OpenVAS should succeed despite CheckMK failure
        self.assertTrue(results['openvas'].success)
        self.assertEqual(len(results['openvas'].data.get('targets', [])), 1)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_multiple_failures_graceful_degradation(self, mock_request):
        """Test graceful degradation when multiple submodules fail."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = self.test_ips[3]  # 80.152.228.15
        
        def mock_response_factory(method, url, **kwargs):
            response = Mock()
            response.content = True
            
            if 'netbox' in url:
                # NetBox times out
                raise Timeout('Connection timeout')
            elif 'checkmk' in url or 'check_mk' in url:
                # CheckMK returns server error
                response.status_code = 500
                response.text = 'Internal server error'
                return response
            elif 'openvas' in url:
                # OpenVAS succeeds
                response.status_code = 200
                response.json.return_value = {'data': []}
                return response
            else:
                response.status_code = 200
                response.json.return_value = {'results': [], 'value': [], 'data': []}
                return response
        
        mock_request.side_effect = mock_response_factory
        
        results = app_module.query_all_enabled(test_ip)
        
        # All submodules should return results (even if failed)
        self.assertEqual(len(results), 3)
        
        # NetBox should fail with timeout
        self.assertFalse(results['netbox'].success)
        self.assertIn('timeout', results['netbox'].error_message.lower())
        
        # CheckMK should fail with API error
        self.assertFalse(results['checkmk'].success)
        self.assertIn('API error', results['checkmk'].error_message)
        
        # OpenVAS should succeed
        self.assertTrue(results['openvas'].success)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_standardized_result_formatting(self, mock_request):
        """Test that all submodules return standardized ApplicationResult format."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = self.test_ips[4]  # 167.235.220.72
        
        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'results': [], 'value': [], 'data': []}
        mock_request.return_value = response
        
        results = app_module.query_all_enabled(test_ip)
        
        # Verify all results follow standardized format
        for submodule_name, result in results.items():
            self.assertIsInstance(result, ApplicationResult)
            self.assertIsInstance(result.success, bool)
            self.assertIsInstance(result.data, dict)
            self.assertIsNotNone(result.source)
            self.assertEqual(result.source, submodule_name)
            
            # If failed, should have error_message
            if not result.success:
                self.assertIsNotNone(result.error_message)
                self.assertIsInstance(result.error_message, str)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_data_correlation_across_submodules(self, mock_request):
        """Test that data from different submodules can be correlated by IP address."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = self.test_ips[0]  # 192.168.143.55
        
        def mock_response_factory(method, url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True
            
            if 'netbox' in url and 'ip-addresses' in url:
                response.json.return_value = {
                    'results': [{
                        'id': 1,
                        'address': str(test_ip),
                        'dns_name': 'server-01.example.com',
                        'description': 'Production web server'
                    }]
                }
            elif 'netbox' in url and 'prefixes' in url:
                response.json.return_value = {'results': []}
            elif 'checkmk' in url or 'check_mk' in url:
                if 'host_config' in url:
                    response.json.return_value = {
                        'value': [{
                            'id': 'server-01',
                            'extensions': {
                                'attributes': {
                                    'ipaddress': str(test_ip),
                                    'alias': 'Production Web Server'
                                }
                            }
                        }]
                    }
                else:
                    response.json.return_value = {'value': []}
            elif 'openvas' in url:
                response.json.return_value = {
                    'data': [{
                        'id': 'target-001',
                        'name': 'server-01.example.com',
                        'hosts': str(test_ip)
                    }]
                }
            else:
                response.json.return_value = {'results': [], 'value': [], 'data': []}
            
            return response
        
        mock_request.side_effect = mock_response_factory
        
        results = app_module.query_all_enabled(test_ip)
        
        # Verify all submodules found data for the same IP
        self.assertTrue(results['netbox'].success)
        self.assertTrue(results['checkmk'].success)
        self.assertTrue(results['openvas'].success)
        
        # Extract IP-related data from each submodule
        netbox_ip = results['netbox'].data['ip_addresses'][0]['address']
        checkmk_ip = results['checkmk'].data['hosts'][0]['extensions']['attributes']['ipaddress']
        openvas_ip = results['openvas'].data['targets'][0]['hosts']
        
        # Verify all submodules reference the same IP
        self.assertEqual(netbox_ip, str(test_ip))
        self.assertEqual(checkmk_ip, str(test_ip))
        self.assertEqual(openvas_ip, str(test_ip))
        
        # Verify hostname correlation
        netbox_hostname = results['netbox'].data['ip_addresses'][0]['dns_name']
        openvas_hostname = results['openvas'].data['targets'][0]['name']
        self.assertEqual(netbox_hostname, openvas_hostname)
    
    def test_validate_submodule_availability(self):
        """Test validation of submodule availability."""
        app_module = ApplicationModule(configurations=self.configurations)
        
        # Validate available submodules
        availability = app_module.validate_submodule_availability(['netbox', 'checkmk', 'openvas'])
        
        self.assertEqual(len(availability), 3)
        self.assertTrue(availability['netbox'])
        self.assertTrue(availability['checkmk'])
        self.assertTrue(availability['openvas'])
        
        # Validate unavailable submodule
        availability = app_module.validate_submodule_availability(['invalid_submodule'])
        self.assertFalse(availability['invalid_submodule'])
    
    def test_credential_manager_integration(self):
        """Test integration with CredentialManager for configuration management."""
        # Create temporary credential file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            credentials = {
                'netbox': {
                    'enabled': True,
                    'base_url': 'https://netbox.example.com',
                    'authentication': {
                        'method': 'api_token',
                        'api_token': 'test_token'
                    }
                },
                'checkmk': {
                    'enabled': True,
                    'base_url': 'https://checkmk.example.com',
                    'authentication': {
                        'method': 'basic_auth',
                        'username': 'automation',
                        'password': 'test_pass'
                    }
                },
                'openvas': {
                    'enabled': False,
                    'base_url': 'https://openvas.example.com',
                    'authentication': {
                        'method': 'api_token',
                        'api_token': 'test_token'
                    }
                }
            }
            json.dump(credentials, f)
            temp_file = f.name
        
        try:
            # Initialize ApplicationModule with credential file
            app_module = ApplicationModule(temp_file)
            
            self.assertIsNotNone(app_module.credential_manager)
            
            # Verify enabled submodules
            enabled = app_module.get_enabled_submodules()
            self.assertEqual(len(enabled), 2)  # Only netbox and checkmk are enabled
            self.assertIn('netbox', enabled)
            self.assertIn('checkmk', enabled)
            self.assertNotIn('openvas', enabled)  # Disabled in config
            
            # Verify credential validation
            validation = app_module.validate_credentials()
            self.assertTrue(validation['netbox'])
            self.assertTrue(validation['checkmk'])
            
        finally:
            # Clean up temporary file
            os.unlink(temp_file)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_authentication_sharing_across_submodules(self, mock_request):
        """Test that authentication is properly managed across multiple submodules."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = self.test_ips[0]
        
        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'results': [], 'value': [], 'data': []}
        mock_request.return_value = response
        
        # Load all submodules
        netbox = app_module.load_submodule('netbox')
        checkmk = app_module.load_submodule('checkmk')
        openvas = app_module.load_submodule('openvas')
        
        # Verify each submodule has its own authentication
        self.assertIn('Authorization', netbox.session.headers)
        self.assertEqual(netbox.session.headers['Authorization'], 'Token netbox_test_token')
        
        self.assertIsNotNone(checkmk.session.auth)
        
        self.assertIn('Authorization', openvas.session.headers)
        self.assertEqual(openvas.session.headers['Authorization'], 'Token openvas_test_token')
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_concurrent_submodule_execution(self, mock_request):
        """Test that multiple submodules can execute queries simultaneously without interference."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = self.test_ips[0]
        
        call_order = []
        
        def mock_response_factory(method, url, **kwargs):
            # Track call order
            if 'netbox' in url:
                call_order.append('netbox')
            elif 'checkmk' in url or 'check_mk' in url:
                call_order.append('checkmk')
            elif 'openvas' in url:
                call_order.append('openvas')
            
            response = Mock()
            response.status_code = 200
            response.content = True
            response.json.return_value = {'results': [], 'value': [], 'data': []}
            return response
        
        mock_request.side_effect = mock_response_factory
        
        results = app_module.query_all_enabled(test_ip)
        
        # Verify all submodules were called
        self.assertIn('netbox', call_order)
        self.assertIn('checkmk', call_order)
        self.assertIn('openvas', call_order)
        
        # Verify all results are present
        self.assertEqual(len(results), 3)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_ipv6_support_across_submodules(self, mock_request):
        """Test that all submodules properly handle IPv6 addresses."""
        app_module = ApplicationModule(configurations=self.configurations)
        test_ip = IPv6Address('2001:db8::1')
        
        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'results': [], 'value': [], 'data': []}
        mock_request.return_value = response
        
        results = app_module.query_all_enabled(test_ip)
        
        # All submodules should handle IPv6 without errors
        self.assertEqual(len(results), 3)
        for submodule_name, result in results.items():
            self.assertIsInstance(result, ApplicationResult)
            # Should either succeed or fail gracefully (not crash)
            self.assertIsNotNone(result.success)
    
    def test_load_unknown_submodule_error(self):
        """Test that loading an unknown submodule raises appropriate error."""
        app_module = ApplicationModule(configurations=self.configurations)
        
        with self.assertRaises(ApplicationError) as context:
            app_module.load_submodule('unknown_submodule')
        
        self.assertIn('Unknown submodule', str(context.exception))
        self.assertIn('unknown_submodule', str(context.exception))
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_empty_configuration_handling(self, mock_request):
        """Test handling of empty configuration (no submodules configured)."""
        app_module = ApplicationModule(configurations={})
        test_ip = self.test_ips[0]
        
        results = app_module.query_all_enabled(test_ip)
        
        # Should return empty results without crashing
        self.assertEqual(len(results), 0)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_submodule_caching(self, mock_request):
        """Test that submodules are cached and reused."""
        app_module = ApplicationModule(configurations=self.configurations)
        
        # Load submodule first time
        netbox1 = app_module.load_submodule('netbox')
        
        # Load same submodule again
        netbox2 = app_module.load_submodule('netbox')
        
        # Should be the same instance (cached)
        self.assertIs(netbox1, netbox2)
        self.assertEqual(len(app_module.loaded_submodules), 1)
    
    def test_set_credential_file(self):
        """Test changing credential file and reloading credentials."""
        # Create first credential file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            credentials1 = {
                'netbox': {
                    'enabled': True,
                    'base_url': 'https://netbox1.example.com',
                    'authentication': {
                        'method': 'api_token',
                        'api_token': 'token1'
                    }
                }
            }
            json.dump(credentials1, f)
            temp_file1 = f.name
        
        # Create second credential file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            credentials2 = {
                'checkmk': {
                    'enabled': True,
                    'base_url': 'https://checkmk1.example.com',
                    'authentication': {
                        'method': 'basic_auth',
                        'username': 'user',
                        'password': 'pass'
                    }
                }
            }
            json.dump(credentials2, f)
            temp_file2 = f.name
        
        try:
            # Initialize with first file
            app_module = ApplicationModule(temp_file1)
            enabled1 = app_module.get_enabled_submodules()
            self.assertIn('netbox', enabled1)
            self.assertNotIn('checkmk', enabled1)
            
            # Change to second file
            app_module.set_credential_file(temp_file2)
            enabled2 = app_module.get_enabled_submodules()
            self.assertNotIn('netbox', enabled2)
            self.assertIn('checkmk', enabled2)
            
            # Verify loaded submodules were cleared
            self.assertEqual(len(app_module.loaded_submodules), 0)
            
        finally:
            os.unlink(temp_file1)
            os.unlink(temp_file2)


if __name__ == '__main__':
    unittest.main()
