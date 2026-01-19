"""
Unit tests for CheckMK submodule.

Tests CheckMK API integration, response parsing, authentication mechanisms,
connection handling, and error handling for various API failure scenarios.
"""

import unittest
from unittest.mock import Mock, patch
from ipaddress import IPv4Address, IPv6Address
from requests.exceptions import Timeout, RequestException

from src.ip_sentinel.modules.application import (
    CheckMKSubmodule,
    ApplicationResult,
    AuthenticationConfig
)


class TestCheckMKSubmodule(unittest.TestCase):
    """Test cases for CheckMK monitoring integration submodule."""

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
            auth_type='basic',
            credentials={'username': 'automation', 'password': 'test_password'},
            base_url='https://checkmk.example.com/site/monitoring',
            timeout=30
        )

    def test_checkmk_initialization_with_config(self):
        """Test CheckMK submodule initialization with authentication config."""
        submodule = CheckMKSubmodule(self.auth_config)

        self.assertIsNotNone(submodule)
        self.assertEqual(submodule.config, self.auth_config)
        self.assertIsNotNone(submodule.session.auth)

    def test_checkmk_initialization_without_config(self):
        """Test CheckMK submodule initialization without config."""
        submodule = CheckMKSubmodule()

        self.assertIsNotNone(submodule)
        self.assertIsNone(submodule.config)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_query_ip_success_with_full_data(self, mock_request):
        """Test successful IP query with comprehensive monitoring data."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[0]  # 192.168.143.55

        # Mock responses for different API calls
        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'host_config/collections/all' in url:
                # Return hosts with matching IP
                response.json.return_value = {
                    'value': [
                        {
                            'id': 'test-server-01',
                            'extensions': {
                                'attributes': {
                                    'ipaddress': str(test_ip),
                                    'alias': 'Test Server 01',
                                    'site': 'main'
                                }
                            }
                        },
                        {
                            'id': 'other-server',
                            'extensions': {
                                'attributes': {
                                    'ipaddress': '192.168.1.100',
                                    'alias': 'Other Server'
                                }
                            }
                        }
                    ]
                }
            elif 'objects/host/test-server-01' in url:
                # Return host status
                response.json.return_value = {
                    'id': 'test-server-01',
                    'extensions': {
                        'state': 0,
                        'state_type': 'hard',
                        'last_check': '2024-01-18T10:30:00Z',
                        'plugin_output': 'OK - Host is up'
                    }
                }
            elif 'service/collections/all' in url:
                # Return services for the host
                response.json.return_value = {
                    'value': [
                        {
                            'id': 'CPU load',
                            'extensions': {
                                'state': 0,
                                'state_type': 'hard',
                                'plugin_output': 'OK - Load average: 0.5',
                                'metrics': {
                                    'load1': {'value': 0.5, 'unit': ''},
                                    'load5': {'value': 0.4, 'unit': ''},
                                    'load15': {'value': 0.3, 'unit': ''}
                                },
                                'check_result': {
                                    'state': 0,
                                    'output': 'OK - Load average: 0.5',
                                    'performance_data': ['load1=0.5', 'load5=0.4']
                                }
                            }
                        },
                        {
                            'id': 'Memory',
                            'extensions': {
                                'state': 0,
                                'state_type': 'hard',
                                'plugin_output': 'OK - 45% used',
                                'metrics': {
                                    'mem_used': {'value': 4500, 'unit': 'MB'},
                                    'mem_total': {'value': 10000, 'unit': 'MB'}
                                },
                                'check_result': {
                                    'state': 0,
                                    'output': 'OK - 45% used'
                                }
                            }
                        }
                    ]
                }
            elif 'notification/collections/all' in url:
                # Return notifications
                response.json.return_value = {
                    'value': [
                        {
                            'id': 'notif-001',
                            'extensions': {
                                'time': '2024-01-18T09:00:00Z',
                                'type': 'email',
                                'contact': 'admin@example.com',
                                'plugin_output': 'Service recovered'
                            }
                        }
                    ]
                }
            elif 'event/collections/all' in url:
                # Return alert history
                response.json.return_value = {
                    'value': [
                        {
                            'id': 'event-001',
                            'extensions': {
                                'time': '2024-01-18T08:00:00Z',
                                'state': 2,
                                'state_type': 'hard',
                                'plugin_output': 'CRITICAL - Service down'
                            }
                        }
                    ]
                }
            else:
                response.json.return_value = {'value': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertIsInstance(result, ApplicationResult)
        self.assertTrue(result.success)
        self.assertIn('CheckMK', result.source)
        self.assertIsNone(result.error_message)

        # Verify data structure
        self.assertIn('hosts', result.data)
        self.assertIn('services', result.data)
        self.assertIn('host_status', result.data)
        self.assertIn('alerts', result.data)
        self.assertIn('notifications', result.data)
        self.assertIn('performance_data', result.data)
        self.assertIn('check_results', result.data)

        # Verify host data
        self.assertEqual(len(result.data['hosts']), 1)
        self.assertEqual(result.data['hosts'][0]['id'], 'test-server-01')
        self.assertEqual(
            result.data['hosts'][0]['extensions']['attributes']['ipaddress'],
            str(test_ip)
        )

        # Verify services data
        self.assertEqual(len(result.data['services']), 2)
        service_names = [s['id'] for s in result.data['services']]
        self.assertIn('CPU load', service_names)
        self.assertIn('Memory', service_names)

        # Verify performance data
        self.assertEqual(len(result.data['performance_data']), 2)
        self.assertEqual(result.data['performance_data'][0]['host'], 'test-server-01')
        self.assertIn('metrics', result.data['performance_data'][0])

        # Verify check results
        self.assertEqual(len(result.data['check_results']), 2)
        self.assertEqual(result.data['check_results'][0]['host'], 'test-server-01')

        # Verify notifications
        self.assertEqual(len(result.data['notifications']), 1)

        # Verify alerts
        self.assertEqual(len(result.data['alerts']), 1)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_query_ip_success_minimal_data(self, mock_request):
        """Test successful IP query with minimal data (no matching hosts)."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[1]  # 192.168.143.1

        # Mock response with no matching hosts
        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {
            'value': [
                {
                    'id': 'other-host',
                    'extensions': {
                        'attributes': {
                            'ipaddress': '10.0.0.1',
                            'alias': 'Other Host'
                        }
                    }
                }
            ]
        }
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        self.assertIn('CheckMK', result.source)
        self.assertEqual(len(result.data['hosts']), 0)
        self.assertEqual(len(result.data['services']), 0)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_query_ipv6_address(self, mock_request):
        """Test querying IPv6 address."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = IPv6Address('2001:db8::1')

        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {
            'value': [
                {
                    'id': 'ipv6-host',
                    'extensions': {
                        'attributes': {
                            'ipaddress': str(test_ip),
                            'alias': 'IPv6 Host'
                        }
                    }
                }
            ]
        }
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        self.assertEqual(len(result.data['hosts']), 1)
        self.assertEqual(
            result.data['hosts'][0]['extensions']['attributes']['ipaddress'],
            str(test_ip)
        )

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_authentication_failure_401(self, mock_request):
        """Test handling of 401 authentication failure."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[2]  # 192.168.141.15

        response = Mock()
        response.status_code = 401
        response.text = 'Invalid credentials'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('CheckMK', result.source)
        self.assertIn('Authentication failed', result.error_message)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_authentication_failure_403(self, mock_request):
        """Test handling of 403 permission denied."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[3]  # 80.152.228.15

        response = Mock()
        response.status_code = 403
        response.text = 'Insufficient permissions'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('Authentication failed', result.error_message)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_connection_timeout(self, mock_request):
        """Test handling of connection timeout."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[4]  # 167.235.220.72

        mock_request.side_effect = Timeout('Connection timed out')

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('CheckMK', result.source)
        self.assertIn('Connection failed', result.error_message)
        self.assertIn('timeout', result.error_message.lower())

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_connection_error(self, mock_request):
        """Test handling of general connection errors."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        mock_request.side_effect = RequestException('Connection refused')

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('Connection failed', result.error_message)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_api_error_404(self, mock_request):
        """Test handling of 404 API errors."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[1]

        response = Mock()
        response.status_code = 404
        response.text = 'Endpoint not found'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('API error', result.error_message)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_api_error_500(self, mock_request):
        """Test handling of 500 server errors."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[2]

        response = Mock()
        response.status_code = 500
        response.text = 'Internal server error'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('API error', result.error_message)
        self.assertIn('500', result.error_message)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_partial_failure_service_query(self, mock_request):
        """Test graceful handling when service query fails but host query succeeds."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[3]

        call_count = [0]

        def mock_response_factory(*args, **kwargs):
            call_count[0] += 1
            response = Mock()
            response.content = True

            # First call: Host config - success
            if call_count[0] == 1:
                response.status_code = 200
                response.json.return_value = {
                    'value': [
                        {
                            'id': 'test-host',
                            'extensions': {
                                'attributes': {
                                    'ipaddress': str(test_ip)
                                }
                            }
                        }
                    ]
                }
            # Second call: Host status - success
            elif call_count[0] == 2:
                response.status_code = 200
                response.json.return_value = {
                    'id': 'test-host',
                    'extensions': {'state': 0}
                }
            # Third call: Services - failure
            elif call_count[0] == 3:
                response.status_code = 500
                response.text = 'Server error'
            # Fourth call: Notifications - success (empty)
            elif call_count[0] == 4:
                response.status_code = 200
                response.json.return_value = {'value': []}
            # Fifth call: Alerts - success (empty)
            else:
                response.status_code = 200
                response.json.return_value = {'value': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        # Should still succeed with partial data
        self.assertTrue(result.success)
        self.assertEqual(len(result.data['hosts']), 1)
        self.assertEqual(len(result.data['services']), 0)  # Service query failed

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_no_config_error(self, mock_request):
        """Test error handling when no configuration is provided."""
        submodule = CheckMKSubmodule()  # No config
        test_ip = self.test_ips[0]

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('No configuration', result.error_message)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_multiple_test_ips(self, mock_request):
        """Test querying all test IP addresses."""
        submodule = CheckMKSubmodule(self.auth_config)

        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'value': []}
        mock_request.return_value = response

        for test_ip in self.test_ips:
            result = submodule.query_ip(test_ip)
            self.assertTrue(result.success)
            self.assertIn('CheckMK', result.source)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_multiple_hosts_same_ip(self, mock_request):
        """Test handling multiple hosts with the same IP address."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'host_config/collections/all' in url:
                # Return multiple hosts with same IP
                response.json.return_value = {
                    'value': [
                        {
                            'id': 'host-01',
                            'extensions': {
                                'attributes': {
                                    'ipaddress': str(test_ip),
                                    'alias': 'Host 01'
                                }
                            }
                        },
                        {
                            'id': 'host-02',
                            'extensions': {
                                'attributes': {
                                    'ipaddress': str(test_ip),
                                    'alias': 'Host 02'
                                }
                            }
                        }
                    ]
                }
            else:
                response.json.return_value = {'value': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        # Should find both hosts
        self.assertEqual(len(result.data['hosts']), 2)
        host_ids = [h['id'] for h in result.data['hosts']]
        self.assertIn('host-01', host_ids)
        self.assertIn('host-02', host_ids)

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_service_with_performance_data(self, mock_request):
        """Test extraction of performance data from services."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'host_config/collections/all' in url:
                response.json.return_value = {
                    'value': [
                        {
                            'id': 'perf-host',
                            'extensions': {
                                'attributes': {'ipaddress': str(test_ip)}
                            }
                        }
                    ]
                }
            elif 'service/collections/all' in url:
                response.json.return_value = {
                    'value': [
                        {
                            'id': 'Disk IO',
                            'extensions': {
                                'metrics': {
                                    'read_ops': {'value': 100, 'unit': 'ops/s'},
                                    'write_ops': {'value': 50, 'unit': 'ops/s'}
                                },
                                'check_result': {
                                    'state': 0,
                                    'output': 'OK - Disk IO normal'
                                }
                            }
                        }
                    ]
                }
            else:
                response.json.return_value = {'value': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        self.assertEqual(len(result.data['performance_data']), 1)
        perf_data = result.data['performance_data'][0]
        self.assertEqual(perf_data['host'], 'perf-host')
        self.assertEqual(perf_data['service'], 'Disk IO')
        self.assertIn('read_ops', perf_data['metrics'])
        self.assertIn('write_ops', perf_data['metrics'])

    @patch('src.ip_sentinel.modules.application.requests.Session.request')
    def test_unexpected_exception_handling(self, mock_request):
        """Test handling of unexpected exceptions."""
        submodule = CheckMKSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        mock_request.side_effect = Exception('Unexpected error')

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('Unexpected error', result.error_message)


if __name__ == '__main__':
    unittest.main()
