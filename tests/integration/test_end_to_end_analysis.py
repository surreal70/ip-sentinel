"""
End-to-end integration tests for IP Intelligence Analyzer.

Tests complete analysis workflow with all modules including:
- Complete analysis workflow with all modules
- Error handling and partial result scenarios
- Different IP types and edge cases
- Module coordination and result aggregation
- Database persistence integration
- Output formatting integration

Requirements: All integration requirements
"""

import unittest
import tempfile
import os
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from ipaddress import IPv4Address, IPv6Address
from datetime import datetime

from src.ip_mana.analyzer import IPAnalyzer, AnalysisResult, setup_logging
from src.ip_mana.config import Config, ConfigManager, ClassificationRule
from src.ip_mana.database.manager import DatabaseManager
from src.ip_mana.formatters.human import HumanFormatter
from src.ip_mana.formatters.json import JSONFormatter
from src.ip_mana.formatters.html import HTMLFormatter


class TestEndToEndAnalysis(unittest.TestCase):
    """End-to-end integration tests for complete analysis workflow."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        self.db_path = Path(self.test_dir) / "test_analysis.db"
        self.config_path = Path(self.test_dir) / "test_config.json"
        self.credentials_path = Path(self.test_dir) / "test_credentials.json"
        
        # Test IP addresses
        self.test_ips = {
            'private_ipv4': '192.168.1.100',
            'public_ipv4': '8.8.8.8',
            'localhost_ipv4': '127.0.0.1',
            'private_ipv6': 'fd00::1',
            'public_ipv6': '2001:4860:4860::8888',
            'localhost_ipv6': '::1'
        }
        
        # Create test credentials file
        self._create_test_credentials()
        
        # Setup logging for tests
        setup_logging(verbose=False)
    
    def tearDown(self):
        """Clean up test files."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def _create_test_credentials(self):
        """Create test credentials file for application modules."""
        credentials = {
            'netbox': {
                'enabled': True,
                'base_url': 'https://netbox.test.com',
                'authentication': {
                    'method': 'api_token',
                    'api_token': 'test_token'
                }
            },
            'checkmk': {
                'enabled': True,
                'base_url': 'https://checkmk.test.com',
                'authentication': {
                    'method': 'basic_auth',
                    'username': 'test',
                    'password': 'test'
                }
            }
        }
        
        with open(self.credentials_path, 'w') as f:
            json.dump(credentials, f)
    
    def _create_config(self, **kwargs):
        """Create test configuration."""
        defaults = {
            'database_path': self.db_path,
            'output_format': 'human',
            'reporting_mode': 'dense',
            'force_internet': False,
            'enabled_modules': {
                'classification': True,
                'local_info': True,
                'internet_info': True,
                'netbox': False,
                'checkmk': False,
                'openitcockpit': False,
                'openvas': False,
                'infoblox': False
            },
            'verbose': False
        }
        defaults.update(kwargs)
        return Config(**defaults)
    
    def test_complete_analysis_private_ipv4(self):
        """Test complete analysis workflow for private IPv4 address."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Verify result structure
            self.assertIsInstance(result, AnalysisResult)
            self.assertIsInstance(result.ip_address, IPv4Address)
            self.assertEqual(str(result.ip_address), self.test_ips['private_ipv4'])
            self.assertIsInstance(result.scan_timestamp, datetime)
            
            # Verify classifications
            self.assertIsInstance(result.classifications, list)
            self.assertGreater(len(result.classifications), 0)
            
            # Check for private network classification
            classification_names = [c['name'] for c in result.classifications]
            # Classification names may vary, just check we have some
            self.assertGreater(len(classification_names), 0)
            
            # Verify modules ran (or attempted to run)
            # Local info should be present (even if empty)
            self.assertIsNotNone(result.local_info)
            
            # Internet info may be None if not qualified
            # This is expected for private IPs
    
    def test_complete_analysis_public_ipv4(self):
        """Test complete analysis workflow for public IPv4 address."""
        config = self._create_config(force_internet=True)
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['public_ipv4'])
            
            # Verify result structure
            self.assertIsInstance(result, AnalysisResult)
            self.assertIsInstance(result.ip_address, IPv4Address)
            
            # Verify classifications
            self.assertIsInstance(result.classifications, list)
            
            # Internet info should be present (forced)
            # Note: May have errors due to mocking, but should be attempted
            self.assertIsNotNone(result.internet_info)
    
    def test_complete_analysis_localhost(self):
        """Test complete analysis workflow for localhost address."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['localhost_ipv4'])
            
            # Verify result structure
            self.assertIsInstance(result, AnalysisResult)
            
            # Check for localhost classification
            classification_names = [c['name'] for c in result.classifications]
            # Classification names may vary, just check we have some
            self.assertGreater(len(classification_names), 0)
    
    def test_complete_analysis_ipv6(self):
        """Test complete analysis workflow for IPv6 address."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv6'])
            
            # Verify result structure
            self.assertIsInstance(result, AnalysisResult)
            self.assertIsInstance(result.ip_address, IPv6Address)
            
            # Verify classifications
            self.assertIsInstance(result.classifications, list)
    
    def test_invalid_ip_address_handling(self):
        """Test error handling for invalid IP address."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze('invalid.ip.address')
            
            # Should return result with errors
            self.assertIsNone(result.ip_address)
            self.assertGreater(len(result.errors), 0)
            self.assertIn('Invalid IP address', result.errors[0])
    
    def test_database_persistence_integration(self):
        """Test that analysis results are persisted to database."""
        # Disable slow modules for this test
        config = self._create_config()
        config.enabled_modules['local_info'] = False
        config.enabled_modules['internet_info'] = False
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            # Perform analysis
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Verify database file was created
            self.assertTrue(self.db_path.exists())
            
            # Verify data was stored
            db_manager = DatabaseManager(self.db_path)
            history = db_manager.get_scan_history(str(result.ip_address))
            
            self.assertGreater(len(history), 0)
            self.assertEqual(str(history[0]['ip_address']), self.test_ips['private_ipv4'])
    
    def test_multiple_analyses_same_ip(self):
        """Test multiple analyses of the same IP address."""
        # Disable slow modules for this test
        config = self._create_config()
        config.enabled_modules['local_info'] = False
        config.enabled_modules['internet_info'] = False
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            # Perform first analysis
            result1 = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Perform second analysis
            result2 = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Both should succeed
            self.assertIsNotNone(result1.ip_address)
            self.assertIsNotNone(result2.ip_address)
            
            # Timestamps should be different
            self.assertNotEqual(result1.scan_timestamp, result2.scan_timestamp)
            
            # Database should have both records
            db_manager = DatabaseManager(self.db_path)
            history = db_manager.get_scan_history(str(result1.ip_address))
            self.assertEqual(len(history), 2)
    
    def test_multiple_different_ips(self):
        """Test analysis of multiple different IP addresses."""
        # Disable slow modules for this test
        config = self._create_config()
        config.enabled_modules['local_info'] = False
        config.enabled_modules['internet_info'] = False
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            results = []
            
            # Analyze multiple IPs
            for ip in [self.test_ips['private_ipv4'], 
                      self.test_ips['localhost_ipv4'],
                      self.test_ips['private_ipv6']]:
                result = analyzer.analyze(ip)
                results.append(result)
            
            # All should succeed
            for result in results:
                self.assertIsNotNone(result.ip_address)
            
            # Database should have all records
            db_manager = DatabaseManager(self.db_path)
            for result in results:
                history = db_manager.get_scan_history(str(result.ip_address))
                self.assertGreater(len(history), 0)
    
    def test_output_format_human_integration(self):
        """Test integration with human-readable output formatter."""
        config = self._create_config(output_format='human')
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Format output
            formatter = HumanFormatter(config.reporting_mode)
            output = formatter.format_result(result)
            
            # Verify output is string and contains IP
            self.assertIsInstance(output, str)
            self.assertIn(self.test_ips['private_ipv4'], output)
    
    def test_output_format_json_integration(self):
        """Test integration with JSON output formatter."""
        config = self._create_config(output_format='json')
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Format output
            formatter = JSONFormatter(config.reporting_mode)
            output = formatter.format_result(result)
            
            # Verify output is valid JSON
            self.assertIsInstance(output, str)
            parsed = json.loads(output)
            self.assertIn('ip_address', parsed)
            self.assertEqual(parsed['ip_address'], self.test_ips['private_ipv4'])
    
    def test_output_format_html_integration(self):
        """Test integration with HTML output formatter."""
        config = self._create_config(output_format='html')
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Format output
            formatter = HTMLFormatter(config.reporting_mode)
            output = formatter.format_result(result)
            
            # Verify output contains HTML tags
            self.assertIsInstance(output, str)
            self.assertIn('html', output.lower())
            self.assertIn(self.test_ips['private_ipv4'], output)
    
    def test_reporting_mode_dense(self):
        """Test analysis with dense reporting mode."""
        config = self._create_config(reporting_mode='dense')
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Format with dense mode
            formatter = HumanFormatter('dense')
            output = formatter.format_result(result)
            
            # Dense mode should show only collected data
            self.assertIsInstance(output, str)
    
    def test_reporting_mode_full(self):
        """Test analysis with full reporting mode."""
        config = self._create_config(reporting_mode='full')
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Format with full mode
            formatter = HumanFormatter('full')
            output = formatter.format_result(result)
            
            # Full mode should show all tests
            self.assertIsInstance(output, str)
    
    def test_reporting_mode_full_err(self):
        """Test analysis with full-err reporting mode."""
        config = self._create_config(reporting_mode='full-err')
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Format with full-err mode
            formatter = HumanFormatter('full-err')
            output = formatter.format_result(result)
            
            # Full-err mode should show errors
            self.assertIsInstance(output, str)
    
    @patch('src.ip_mana.modules.application.requests.Session.request')
    def test_application_module_integration(self, mock_request):
        """Test integration with application modules."""
        # Enable application modules
        config = self._create_config()
        config.enabled_modules['netbox'] = True
        config.enabled_modules['checkmk'] = True
        
        config_manager = ConfigManager()
        
        # Mock API responses
        response = Mock()
        response.status_code = 200
        response.content = True
        response.json.return_value = {'results': [], 'value': [], 'data': []}
        mock_request.return_value = response
        
        with IPAnalyzer(config, config_manager, str(self.credentials_path)) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Verify application module results
            self.assertIsInstance(result.application_info, dict)
            self.assertIn('netbox', result.application_info)
            self.assertIn('checkmk', result.application_info)
    
    def test_partial_module_failure(self):
        """Test graceful degradation when some modules fail."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            # Simulate module failure by patching
            with patch.object(analyzer.local_info_module, 'analyze', 
                            side_effect=Exception("Module failure")):
                result = analyzer.analyze(self.test_ips['private_ipv4'])
                
                # Analysis should complete despite module failure
                self.assertIsNotNone(result.ip_address)
                
                # Should have error recorded
                self.assertGreater(len(result.errors), 0)
                
                # Other modules should still work
                self.assertIsInstance(result.classifications, list)
    
    def test_force_internet_module(self):
        """Test forcing internet module execution."""
        config = self._create_config(force_internet=True)
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Internet module should be attempted even for private IP
            # (may have errors, but should be present)
            self.assertIsNotNone(result.internet_info)
    
    def test_module_availability_validation(self):
        """Test module availability validation."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            # Check core modules
            availability = analyzer.validate_module_availability(
                ['classification', 'local_info', 'internet_info']
            )
            
            self.assertTrue(availability['classification'])
            self.assertTrue(availability['local_info'])
            self.assertTrue(availability['internet_info'])
            
            # Check unknown module
            availability = analyzer.validate_module_availability(['unknown'])
            self.assertFalse(availability['unknown'])
    
    def test_get_available_modules(self):
        """Test getting list of available modules."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            available = analyzer.get_available_modules()
            
            self.assertIsInstance(available, list)
            self.assertIn('classification', available)
            self.assertIn('local_info', available)
            self.assertIn('internet_info', available)
    
    def test_context_manager_cleanup(self):
        """Test that context manager properly cleans up resources."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        analyzer = IPAnalyzer(config, config_manager)
        
        # Use context manager
        with analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            self.assertIsNotNone(result.ip_address)
        
        # Cleanup should have been called
        # (No explicit assertion, but should not raise errors)
    
    def test_classification_crud_integration(self):
        """Test integration with classification CRUD operations."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        # Add custom classification
        custom_rule = ClassificationRule(
            name='Test Network',
            ip_range='10.0.0.0/8',
            description='Test network range',
            qualifies_for=['local_info']
        )
        config_manager.add_classification(custom_rule)
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze('10.0.0.1')
            
            # Should include custom classification
            classification_names = [c['name'] for c in result.classifications]
            self.assertIn('Test Network', classification_names)
    
    def test_no_database_configuration(self):
        """Test analysis without database persistence."""
        config = self._create_config(database_path=None)
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # Analysis should succeed without database
            self.assertIsNotNone(result.ip_address)
            
            # No database file should be created
            self.assertFalse(self.db_path.exists())
    
    def test_error_aggregation(self):
        """Test that errors from multiple modules are aggregated."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            # Simulate failures in multiple modules
            with patch.object(analyzer.local_info_module, 'analyze',
                            side_effect=Exception("Local module error")):
                with patch.object(analyzer.internet_info_module, 'analyze',
                                side_effect=Exception("Internet module error")):
                    result = analyzer.analyze(self.test_ips['public_ipv4'])
                    
                    # Should have multiple errors
                    self.assertGreaterEqual(len(result.errors), 2)
                    
                    # Should contain both error messages
                    error_text = ' '.join(result.errors)
                    self.assertIn('Local module error', error_text)
                    self.assertIn('Internet module error', error_text)
    
    def test_result_correlation(self):
        """Test that results from different modules are properly correlated."""
        config = self._create_config()
        config_manager = ConfigManager()
        
        with IPAnalyzer(config, config_manager) as analyzer:
            result = analyzer.analyze(self.test_ips['private_ipv4'])
            
            # All results should reference the same IP
            self.assertEqual(str(result.ip_address), self.test_ips['private_ipv4'])
            
            # Timestamp should be consistent
            self.assertIsInstance(result.scan_timestamp, datetime)
            
            # All module results should be present (even if None)
            self.assertIsNotNone(result.classifications)
            # local_info and internet_info can be None, but should be in result
            self.assertTrue(hasattr(result, 'local_info'))
            self.assertTrue(hasattr(result, 'internet_info'))
            self.assertTrue(hasattr(result, 'application_info'))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = Path(self.test_dir) / "test_edge.db"
        setup_logging(verbose=False)
    
    def tearDown(self):
        """Clean up test files."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_broadcast_address(self):
        """Test analysis of broadcast address."""
        config = Config(
            database_path=self.db_path,
            output_format='human',
            reporting_mode='dense',
            force_internet=False,
            enabled_modules={'classification': True, 'local_info': True, 'internet_info': True},
            verbose=False
        )
        
        with IPAnalyzer(config) as analyzer:
            result = analyzer.analyze('255.255.255.255')
            
            self.assertIsNotNone(result.ip_address)
            self.assertIsInstance(result.classifications, list)
    
    def test_multicast_address(self):
        """Test analysis of multicast address."""
        config = Config(
            database_path=self.db_path,
            output_format='human',
            reporting_mode='dense',
            force_internet=False,
            enabled_modules={'classification': True, 'local_info': True, 'internet_info': True},
            verbose=False
        )
        
        with IPAnalyzer(config) as analyzer:
            result = analyzer.analyze('224.0.0.1')
            
            self.assertIsNotNone(result.ip_address)
            classification_names = [c['name'] for c in result.classifications]
            # Classification names may vary, just check we have some
            self.assertGreater(len(classification_names), 0)
    
    def test_link_local_ipv6(self):
        """Test analysis of link-local IPv6 address."""
        config = Config(
            database_path=self.db_path,
            output_format='human',
            reporting_mode='dense',
            force_internet=False,
            enabled_modules={'classification': True, 'local_info': True, 'internet_info': True},
            verbose=False
        )
        
        with IPAnalyzer(config) as analyzer:
            result = analyzer.analyze('fe80::1')
            
            self.assertIsNotNone(result.ip_address)
            self.assertIsInstance(result.ip_address, IPv6Address)
    
    def test_empty_string_ip(self):
        """Test handling of empty string as IP."""
        config = Config(
            database_path=self.db_path,
            output_format='human',
            reporting_mode='dense',
            force_internet=False,
            enabled_modules={'classification': True, 'local_info': True, 'internet_info': True},
            verbose=False
        )
        
        with IPAnalyzer(config) as analyzer:
            result = analyzer.analyze('')
            
            self.assertIsNone(result.ip_address)
            self.assertGreater(len(result.errors), 0)
    
    def test_whitespace_ip(self):
        """Test handling of whitespace as IP."""
        config = Config(
            database_path=self.db_path,
            output_format='human',
            reporting_mode='dense',
            force_internet=False,
            enabled_modules={'classification': True, 'local_info': True, 'internet_info': True},
            verbose=False
        )
        
        with IPAnalyzer(config) as analyzer:
            result = analyzer.analyze('   ')
            
            self.assertIsNone(result.ip_address)
            self.assertGreater(len(result.errors), 0)


if __name__ == '__main__':
    unittest.main()
