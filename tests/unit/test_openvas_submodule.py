"""
Unit tests for OpenVAS submodule.

Tests OpenVAS API integration, response parsing, authentication mechanisms,
connection handling, and error handling for various API failure scenarios.
"""

import unittest
from unittest.mock import Mock, patch
from ipaddress import IPv4Address, IPv6Address
from requests.exceptions import Timeout, RequestException

from src.ip_mana.modules.application import (
    OpenVASSubmodule,
    ApplicationResult,
    AuthenticationConfig
)


class TestOpenVASSubmodule(unittest.TestCase):
    """Test cases for OpenVAS vulnerability assessment integration submodule."""

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
            credentials={'api_key': 'test_openvas_token_12345'},
            base_url='https://openvas.example.com',
            timeout=60
        )

    def test_openvas_initialization_with_config(self):
        """Test OpenVAS submodule initialization with authentication config."""
        submodule = OpenVASSubmodule(self.auth_config)

        self.assertIsNotNone(submodule)
        self.assertEqual(submodule.config, self.auth_config)
        self.assertIn('Authorization', submodule.session.headers)
        self.assertEqual(
            submodule.session.headers['Authorization'],
            'Token test_openvas_token_12345')

    def test_openvas_initialization_without_config(self):
        """Test OpenVAS submodule initialization without config."""
        submodule = OpenVASSubmodule()

        self.assertIsNotNone(submodule)
        self.assertIsNone(submodule.config)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_query_ip_success_with_full_data(self, mock_request):
        """Test successful IP query with comprehensive vulnerability data."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[0]  # 192.168.143.55

        # Mock responses for different API calls
        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'targets' in url:
                response.json.return_value = {
                    'data': [{
                        'id': 'target-001',
                        'name': 'Test Target',
                        'hosts': str(test_ip),
                        'port_list': {'id': 'port-list-001', 'name': 'All TCP and UDP'},
                        'alive_test': 'ICMP Ping'
                    }]
                }
            elif 'tasks' in url:
                response.json.return_value = {
                    'data': [{
                        'id': 'task-001',
                        'name': 'Vulnerability Scan',
                        'status': 'Done',
                        'progress': 100,
                        'target': {'id': 'target-001'},
                        'creation_time': '2024-01-15T10:00:00Z',
                        'modification_time': '2024-01-15T11:30:00Z',
                        'last_report': {
                            'id': 'report-001',
                            'timestamp': '2024-01-15T11:30:00Z'
                        }
                    }]
                }
            elif 'reports' in url and 'results' not in url:
                response.json.return_value = {
                    'data': [{
                        'id': 'report-001',
                        'task': {'id': 'task-001'},
                        'timestamp': '2024-01-15T11:30:00Z',
                        'scan_start': '2024-01-15T10:00:00Z',
                        'scan_end': '2024-01-15T11:30:00Z',
                        'result_count': {'total': 5, 'high': 2, 'medium': 2, 'low': 1}
                    }]
                }
            elif 'results' in url:
                response.json.return_value = {
                    'data': [
                        {
                            'id': 'result-001',
                            'name': 'SQL Injection Vulnerability',
                            'severity': 9.8,
                            'threat': 'Critical',
                            'host': str(test_ip),
                            'port': '443/tcp',
                            'description': 'SQL injection vulnerability detected in web application',
                            'solution': 'Update to latest version and use parameterized queries',
                            'nvt': {
                                'oid': '1.3.6.1.4.1.25623.1.0.12345',
                                'cvss_base': '9.8',
                                'refs': {
                                    'ref': [
                                        {'type': 'cve', 'id': 'CVE-2024-1234'},
                                        {'type': 'cve', 'id': 'CVE-2024-5678'}
                                    ]
                                }
                            }
                        },
                        {
                            'id': 'result-002',
                            'name': 'Outdated SSL/TLS Protocol',
                            'severity': 7.5,
                            'threat': 'High',
                            'host': str(test_ip),
                            'port': '443/tcp',
                            'description': 'Server supports outdated SSL/TLS protocols',
                            'solution': 'Disable SSLv3 and TLS 1.0',
                            'nvt': {
                                'oid': '1.3.6.1.4.1.25623.1.0.67890',
                                'cvss_base': '7.5',
                                'refs': {
                                    'ref': {'type': 'cve', 'id': 'CVE-2024-9999'}
                                }
                            }
                        },
                        {
                            'id': 'result-003',
                            'name': 'Missing Security Headers',
                            'severity': 5.3,
                            'threat': 'Medium',
                            'host': str(test_ip),
                            'port': '80/tcp',
                            'description': 'Web server missing security headers',
                            'solution': 'Add X-Frame-Options, X-Content-Type-Options headers',
                            'nvt': {
                                'oid': '1.3.6.1.4.1.25623.1.0.11111',
                                'cvss_base': '5.3',
                                'refs': {'ref': []}
                            }
                        }
                    ]
                }
            else:
                response.json.return_value = {'data': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertIsInstance(result, ApplicationResult)
        self.assertTrue(result.success)
        self.assertEqual(result.source, 'openvas')
        self.assertIsNone(result.error_message)

        # Verify data structure
        self.assertIn('targets', result.data)
        self.assertIn('tasks', result.data)
        self.assertIn('reports', result.data)
        self.assertIn('results', result.data)
        self.assertIn('vulnerabilities', result.data)
        self.assertIn('cve_information', result.data)
        self.assertIn('scan_history', result.data)
        self.assertIn('severity_summary', result.data)

        # Verify target data
        self.assertEqual(len(result.data['targets']), 1)
        self.assertEqual(result.data['targets'][0]['id'], 'target-001')
        self.assertEqual(result.data['targets'][0]['hosts'], str(test_ip))

        # Verify task data
        self.assertEqual(len(result.data['tasks']), 1)
        self.assertEqual(result.data['tasks'][0]['id'], 'task-001')
        self.assertEqual(result.data['tasks'][0]['status'], 'Done')

        # Verify report data
        self.assertEqual(len(result.data['reports']), 1)
        self.assertEqual(result.data['reports'][0]['id'], 'report-001')

        # Verify results data
        self.assertEqual(len(result.data['results']), 3)

        # Verify vulnerabilities
        self.assertEqual(len(result.data['vulnerabilities']), 3)
        self.assertEqual(
            result.data['vulnerabilities'][0]['name'],
            'SQL Injection Vulnerability')
        self.assertEqual(result.data['vulnerabilities'][0]['severity'], 9.8)
        self.assertEqual(result.data['vulnerabilities'][0]['threat'], 'Critical')

        # Verify CVE information
        self.assertGreater(len(result.data['cve_information']), 0)
        cve_ids = [cve['cve_id'] for cve in result.data['cve_information']]
        self.assertIn('CVE-2024-1234', cve_ids)
        self.assertIn('CVE-2024-5678', cve_ids)
        self.assertIn('CVE-2024-9999', cve_ids)

        # Verify scan history
        self.assertEqual(len(result.data['scan_history']), 1)
        self.assertEqual(result.data['scan_history'][0]['task_id'], 'task-001')

        # Verify severity summary
        severity_summary = result.data['severity_summary']
        self.assertEqual(severity_summary['critical'], 1)
        self.assertEqual(severity_summary['high'], 1)
        self.assertEqual(severity_summary['medium'], 1)
        self.assertEqual(severity_summary['low'], 0)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_query_ip_success_minimal_data(self, mock_request):
        """Test successful IP query with no vulnerabilities found."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[1]  # 192.168.143.1

        # Mock minimal response - no targets found
        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'data': []}
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        self.assertEqual(result.source, 'openvas')
        self.assertEqual(len(result.data['targets']), 0)
        self.assertEqual(len(result.data['vulnerabilities']), 0)
        self.assertEqual(result.data['severity_summary']['critical'], 0)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_query_ipv6_address(self, mock_request):
        """Test querying IPv6 address."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = IPv6Address('2001:db8::1')

        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {
            'data': [{
                'id': 'target-ipv6',
                'hosts': str(test_ip),
                'name': 'IPv6 Target'
            }]
        }
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        self.assertEqual(result.data['targets'][0]['hosts'], str(test_ip))

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_authentication_failure_401(self, mock_request):
        """Test handling of 401 authentication failure."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[2]  # 192.168.141.15

        response = Mock()
        response.status_code = 401
        response.text = 'Invalid API token'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertEqual(result.source, 'openvas')
        self.assertIn('Authentication failed', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_authentication_failure_403(self, mock_request):
        """Test handling of 403 permission denied."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[3]  # 80.152.228.15

        response = Mock()
        response.status_code = 403
        response.text = 'Insufficient permissions to access vulnerability data'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('Authentication failed', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_connection_timeout(self, mock_request):
        """Test handling of connection timeout."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[4]  # 167.235.220.72

        mock_request.side_effect = Timeout('Connection timed out after 60 seconds')

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertEqual(result.source, 'openvas')
        self.assertIn('Connection failed', result.error_message)
        self.assertIn('timeout', result.error_message.lower())

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_connection_error(self, mock_request):
        """Test handling of general connection errors."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        mock_request.side_effect = RequestException(
            'Connection refused - OpenVAS service unavailable')

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('Connection failed', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_api_error_404(self, mock_request):
        """Test handling of 404 API errors."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[1]

        response = Mock()
        response.status_code = 404
        response.text = 'Endpoint not found'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('API error', result.error_message)
        self.assertIn('404', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_api_error_500(self, mock_request):
        """Test handling of 500 server errors."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[2]

        response = Mock()
        response.status_code = 500
        response.text = 'Internal server error in vulnerability scanner'
        mock_request.return_value = response

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('API error', result.error_message)
        self.assertIn('500', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_partial_failure_task_query(self, mock_request):
        """Test graceful handling when task query fails but target query succeeds."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[3]

        call_count = [0]

        def mock_response_factory(*args, **kwargs):
            call_count[0] += 1
            response = Mock()
            response.content = True

            # First call: Targets - success
            if call_count[0] == 1:
                response.status_code = 200
                response.json.return_value = {
                    'data': [{
                        'id': 'target-001',
                        'hosts': str(test_ip)
                    }]
                }
            # Second call: Tasks - failure
            elif call_count[0] == 2:
                response.status_code = 500
                response.text = 'Server error'

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        # Should still succeed with partial data
        self.assertTrue(result.success)
        self.assertEqual(len(result.data['targets']), 1)
        self.assertEqual(len(result.data['tasks']), 0)  # Task query failed

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_no_config_error(self, mock_request):
        """Test error handling when no configuration is provided."""
        submodule = OpenVASSubmodule()  # No config
        test_ip = self.test_ips[0]

        result = submodule.query_ip(test_ip)

        self.assertFalse(result.success)
        self.assertIn('No configuration', result.error_message)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_multiple_test_ips(self, mock_request):
        """Test querying all test IP addresses."""
        submodule = OpenVASSubmodule(self.auth_config)

        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'data': []}
        mock_request.return_value = response

        for test_ip in self.test_ips:
            result = submodule.query_ip(test_ip)
            self.assertTrue(result.success)
            self.assertEqual(result.source, 'openvas')

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_severity_classification(self, mock_request):
        """Test that vulnerabilities are correctly classified by severity."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'targets' in url:
                response.json.return_value = {
                    'data': [{'id': 'target-001', 'hosts': str(test_ip)}]
                }
            elif 'tasks' in url:
                response.json.return_value = {
                    'data': [{'id': 'task-001', 'status': 'Done', 'progress': 100}]
                }
            elif 'reports' in url and 'results' not in url:
                response.json.return_value = {
                    'data': [{'id': 'report-001', 'task': {'id': 'task-001'}}]
                }
            elif 'results' in url:
                response.json.return_value = {'data': [{'id': 'r1',
                                                        'name': 'Critical Vuln',
                                                        'severity': 10.0,
                                                        'threat': 'Critical',
                                                        'host': str(test_ip),
                                                        'port': '443/tcp',
                                                        'nvt': {'oid': '1',
                                                                'refs': {'ref': []}}},
                                                       {'id': 'r2',
                                                        'name': 'High Vuln',
                                                        'severity': 8.5,
                                                        'threat': 'High',
                                                        'host': str(test_ip),
                                                        'port': '443/tcp',
                                                        'nvt': {'oid': '2',
                                                                'refs': {'ref': []}}},
                                                       {'id': 'r3',
                                                        'name': 'Medium Vuln',
                                                        'severity': 5.0,
                                                        'threat': 'Medium',
                                                        'host': str(test_ip),
                                                        'port': '80/tcp',
                                                        'nvt': {'oid': '3',
                                                                'refs': {'ref': []}}},
                                                       {'id': 'r4',
                                                        'name': 'Low Vuln',
                                                        'severity': 2.0,
                                                        'threat': 'Low',
                                                        'host': str(test_ip),
                                                        'port': '22/tcp',
                                                        'nvt': {'oid': '4',
                                                                'refs': {'ref': []}}},
                                                       {'id': 'r5',
                                                        'name': 'Info',
                                                        'severity': 0.0,
                                                        'threat': 'Log',
                                                        'host': str(test_ip),
                                                        'port': '22/tcp',
                                                        'nvt': {'oid': '5',
                                                                'refs': {'ref': []}}}]}
            else:
                response.json.return_value = {'data': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        severity_summary = result.data['severity_summary']
        self.assertEqual(severity_summary['critical'], 1)
        self.assertEqual(severity_summary['high'], 1)
        self.assertEqual(severity_summary['medium'], 1)
        self.assertEqual(severity_summary['low'], 1)
        self.assertEqual(severity_summary['log'], 1)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_cve_extraction_from_results(self, mock_request):
        """Test that CVE information is correctly extracted from vulnerability results."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'targets' in url:
                response.json.return_value = {
                    'data': [{'id': 'target-001', 'hosts': str(test_ip)}]
                }
            elif 'tasks' in url:
                response.json.return_value = {
                    'data': [{'id': 'task-001', 'status': 'Done', 'progress': 100}]
                }
            elif 'reports' in url and 'results' not in url:
                response.json.return_value = {
                    'data': [{'id': 'report-001', 'task': {'id': 'task-001'}}]
                }
            elif 'results' in url:
                response.json.return_value = {
                    'data': [{
                        'id': 'result-001',
                        'name': 'Apache Struts RCE',
                        'severity': 9.8,
                        'threat': 'Critical',
                        'host': str(test_ip),
                        'port': '8080/tcp',
                        'nvt': {
                            'oid': '1.3.6.1.4.1.25623.1.0.99999',
                            'refs': {
                                'ref': [
                                    {'type': 'cve', 'id': 'CVE-2017-5638'},
                                    {'type': 'url', 'id': 'https://example.com/advisory'},
                                    {'type': 'cve', 'id': 'CVE-2017-9805'}
                                ]
                            }
                        }
                    }]
                }
            else:
                response.json.return_value = {'data': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        cve_info = result.data['cve_information']
        self.assertEqual(len(cve_info), 2)  # Only CVE refs, not URL
        cve_ids = [cve['cve_id'] for cve in cve_info]
        self.assertIn('CVE-2017-5638', cve_ids)
        self.assertIn('CVE-2017-9805', cve_ids)

    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_scan_history_extraction(self, mock_request):
        """Test that scan history is correctly extracted from tasks."""
        submodule = OpenVASSubmodule(self.auth_config)
        test_ip = self.test_ips[0]

        def mock_response_factory(url, **kwargs):
            response = Mock()
            response.status_code = 200
            response.content = True

            if 'targets' in url:
                response.json.return_value = {
                    'data': [{'id': 'target-001', 'hosts': str(test_ip)}]
                }
            elif 'tasks' in url:
                response.json.return_value = {
                    'data': [
                        {
                            'id': 'task-001',
                            'name': 'Weekly Scan',
                            'status': 'Done',
                            'progress': 100,
                            'creation_time': '2024-01-01T00:00:00Z',
                            'modification_time': '2024-01-01T02:00:00Z',
                            'last_report': {
                                'id': 'report-001',
                                'timestamp': '2024-01-01T02:00:00Z'}},
                        {
                            'id': 'task-002',
                            'name': 'Monthly Deep Scan',
                            'status': 'Running',
                            'progress': 45,
                            'creation_time': '2024-01-15T00:00:00Z',
                            'modification_time': '2024-01-15T01:00:00Z',
                            'last_report': {}}]}
            else:
                response.json.return_value = {'data': []}

            return response

        mock_request.side_effect = mock_response_factory

        result = submodule.query_ip(test_ip)

        self.assertTrue(result.success)
        scan_history = result.data['scan_history']
        self.assertEqual(len(scan_history), 2)
        self.assertEqual(scan_history[0]['task_name'], 'Weekly Scan')
        self.assertEqual(scan_history[0]['status'], 'Done')
        self.assertEqual(scan_history[1]['task_name'], 'Monthly Deep Scan')
        self.assertEqual(scan_history[1]['status'], 'Running')
        self.assertEqual(scan_history[1]['progress'], 45)


if __name__ == '__main__':
    unittest.main()
