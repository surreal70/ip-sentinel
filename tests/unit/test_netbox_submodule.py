"""
Unit tests for NetBox submodule.

Tests NetBox API integration, response parsing, authentication mechanisms,
connection handling, and error handling for various API failure scenarios.
"""

import unittest
from unittest.mock import Mock, patch
from ipaddress import IPv4Address, IPv6Address
from requests.exceptions import Timeout, RequestException

from src.ip_mana.modules.application import (
    NetBoxSubmodule,
    ApplicationResult,
    AuthenticationConfig
)


class TestNetBoxSubmodule(unittest.TestCase):
    """Test cases for NetBox IPAM integration submodule."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_ips = [
            IPv4Address('192.168.143.55'),
            IPv4Address('192.168.143.1'),
            IPv4Address('192.168.141.15'),
            IPv4Address('80.152.228.15'),
            IPv4Address('167.235.220.72')
        ]

        self.auth_config = AuthenticationConfig(
            auth_type='api_key',
            credentials={'api_key': 'test_token_12345'},
            base_url='https://netbox.example.com',
            timeout=30
        )

    def test_netbox_initialization_with_config(self):
        """Test NetBox submodule initialization with authentication config."""
        submodule = NetBoxSubmodule(self.auth_config)

        self.assertIsNotNone(submodule)
        self.assertEqual(submodule.config, self.auth_config)
        self.assertIn('Authorization', submodule.session.headers)
        self.assertEqual(
            submodule.session.headers['Authorization'],
            'Token test_token_12345')

    def test_netbox_initialization_without_config(self):
        """Test NetBox submodule initialization without config."""
        submodule = NetBoxSubmodule()

        self.assertIsNotNone(submodule)
        self.assertIsNone(submodule.config)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_query_ip_success_with_full_data(self, mock_request):
        """Test successful IP query with comprehensive data including devices, interfaces, VLANs, and VRFs."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[0]  # 192.168.143.55

        # Mock responses for different API calls
        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'ip-addresses' in url:
                response.json.return_value = {
                    'results': [{
                        'id': 1,
                        'address': str(test_ip),
                        'status': {'value': 'active'},
                        'dns_name': 'test-host.example.com',
                        'description': 'Test server',
                        'assigned_object': {
                            'id': 10,
                            'object_type': 'dcim.interface',
                            'name': 'eth0'
                        },
                        'vrf': {
                            'id': 5,
                            'name': 'PROD-VRF'
                        }
                    }]
                }
            elif 'prefixes' in url:
                response.json.return_value = {
                    'results': [{
                        'id': 2,
                        'prefix': '192.168.143.0/24',
                        'status': {'value': 'active'},
                        'description': 'Test subnet',
                        'vlan': {
                            'id': 20,
                            'vid': 143,
                            'name': 'VLAN143'
                        }
                    }]
                }
            elif 'interfaces/10' in url:
                response.json.return_value = {
                    'id': 10,
                    'name': 'eth0',
                    'type': {'value': '1000base-t'},
                    'device': {
                        'id': 100,
                        'name': 'test-server-01'
                    }
                }
            elif 'devices/100' in url:
                response.json.return_value = {
                    'id': 100,
                    'name': 'test-server-01',
                    'device_type': {'model': 'Dell R640'},
                    'site': {'name': 'DC1'},
                    'status': {'value': 'active'}
                }
            elif 'vrfs/5' in url:
                response.json.return_value = {
                    'id': 5,
                    'name': 'PROD-VRF',
                    'rd': '65000:100',
                    'description': 'Production VRF'
                }
            elif 'vlans/20' in url:
                response.json.return_value = {
                    'id': 20,
                    'vid': 143,
                    'name': 'VLAN143',
                    'status': {'value': 'active'}
                }
            else:
                response.json.return_value = {'results': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertIsInstance(result, ApplicationResult)
        self.assertTrue(result.success)
        self.assertEqual(result.source, 'netbox')
        self.assertIsNone(result.error_message)

        # Verify data structure
        self.assertIn('ip_addresses', result.data)
        self.assertIn('prefixes', result.data)
        self.assertIn('devices', result.data)
        self.assertIn('interfaces', result.data)
        self.assertIn('vlans', result.data)
        self.assertIn('vrfs', result.data)

        # Verify IP address data
        self.assertEqual(len(result.data['ip_addresses']), 1)
        self.assertEqual(result.data['ip_addresses'][0]['address'], str(test_ip))

        # Verify prefix data
        self.assertEqual(len(result.data['prefixes']), 1)
        self.assertEqual(result.data['prefixes'][0]['prefix'], '192.168.143.0/24')

        # Verify device data
        self.assertEqual(len(result.data['devices']), 1)
        self.assertEqual(result.data['devices'][0]['name'], 'test-server-01')

        # Verify interface data
        self.assertEqual(len(result.data['interfaces']), 1)
        self.assertEqual(result.data['interfaces'][0]['name'], 'eth0')

        # Verify VLAN data
        self.assertEqual(len(result.data['vlans']), 1)
        self.assertEqual(result.data['vlans'][0]['vid'], 143)

        # Verify VRF data
        self.assertEqual(len(result.data['vrfs']), 1)
        self.assertEqual(result.data['vrfs'][0]['name'], 'PROD-VRF')

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_query_ip_success_minimal_data(self, mock_request):
        """Test successful IP query with minimal data (no associated resources)."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[1]  # 192.168.143.1

        # Mock minimal response
        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'results': []}
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        self.assertEqual(result.source, 'netbox')
        self.assertEqual(len(result.data['ip_addresses']), 0)
        self.assertEqual(len(result.data['prefixes']), 0)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_query_ipv6_address(self, mock_request):
        """Test querying IPv6 address."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = IPv6Address('2001:db8::1')

        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {
            'results': [{
                'id': 1,
                'address': str(test_ip),
                'status': {'value': 'active'}
            }]
        }
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        self.assertEqual(result.data['ip_addresses'][0]['address'], str(test_ip))

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_authentication_failure_401(self, mock_request):
        """Test handling of 401 authentication failure."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[2]  # 192.168.141.15

        response = Mock()
        response.status_code = 401
        response.text = 'Invalid token'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertEqual(result.source, 'netbox')
        self.assertIn('Authentication failed', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_authentication_failure_403(self, mock_request):
        """Test handling of 403 permission denied."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[3]  # 80.152.228.15

        response = Mock()
        response.status_code = 403
        response.text = 'Insufficient permissions'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('Authentication failed', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_connection_timeout(self, mock_request):
        """Test handling of connection timeout."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[4]  # 167.235.220.72

        mock_request.side_effect = Timeout('Connection timed out')

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertEqual(result.source, 'netbox')
        self.assertIn('Connection failed', result.error_message)
        self.assertIn('timeout', result.error_message.lower())

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_connection_error(self, mock_request):
        """Test handling of general connection errors."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        mock_request.side_effect = RequestException('Connection refused')

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('Connection failed', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_api_error_404(self, mock_request):
        """Test handling of 404 API errors."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[1]

        response = Mock()
        response.status_code = 404
        response.text = 'Not found'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('API error', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_api_error_500(self, mock_request):
        """Test handling of 500 server errors."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[2]

        response = Mock()
        response.status_code = 500
        response.text = 'Internal server error'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('API error', result.error_message)
        self.assertIn('500', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_partial_failure_interface_query(self, mock_request):
        """Test graceful handling when interface query fails but IP query succeeds."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[3]

        call_count = [0]

        def mock_response_factory(*args, **kwargs):
            call_count[0] += 1
            response = Mock()
            response.content = True

            # First call: IP addresses - success
            if call_count[0] == 1:
                response.status_code = 200
                response.json.return_value = {
                    'results': [{
                        'id': 1,
                        'address': str(test_ip),
                        'assigned_object': {
                            'id': 10,
                            'object_type': 'dcim.interface'
                        }
                    }]
                }
            # Second call: Prefixes - success
            elif call_count[0] == 2:
                response.status_code = 200
                response.json.return_value = {'results': []}
            # Third call: Interface - failure
            elif call_count[0] == 3:
                response.status_code = 500
                response.text = 'Server error'

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        # Should still succeed with partial data
        self.assertTrue(result.success)
        self.assertEqual(len(result.data['ip_addresses']), 1)
        self.assertEqual(len(result.data['interfaces']), 0)  # Interface query failed

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_no_config_error(self, mock_request):
        """Test error handling when no configuration is provided."""
        submodule = NetBoxSubmodule()  # No config
        test_ip = self.test_ips[0]

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('No configuration', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_multiple_test_ips(self, mock_request):
        """Test querying all test IP addresses."""
        submodule = NetBoxSubmodule(self.auth_config)

        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'results': []}
        mock_request.return_value = response

        for test_ip in self.test_ips:
            result = submodule.query_ip(test_ip)
            self.assertTrue(result.success)
            self.assertEqual(result.source, 'netbox')

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_vlan_deduplication(self, mock_request):
        """Test that duplicate VLANs are not added multiple times."""
        submodule = NetBoxSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'ip-addresses' in url:
                response.json.return_value = {'results': []}
            elif 'prefixes' in url:
                # Return two prefixes with the same VLAN
                response.json.return_value = {
                    'results': [
                        {
                            'id': 1,
                            'prefix': '192.168.143.0/24',
                            'vlan': {'id': 20, 'vid': 143}
                        },
                        {
                            'id': 2,
                            'prefix': '192.168.143.0/25',
                            'vlan': {'id': 20, 'vid': 143}
                        }
                    ]
                }
            elif 'vlans/20' in url:
                response.json.return_value = {
                    'id': 20,
                    'vid': 143,
                    'name': 'VLAN143'
                }
            else:
                response.json.return_value = {'results': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        # Should only have one VLAN despite two prefixes referencing it
        self.assertEqual(len(result.data['vlans']), 1)
        self.assertEqual(result.data['vlans'][0]['id'], 20)


if __name__ == '__main__':
    unittest.main()
