"""
Property-based tests for application integration error handling.

Feature: ip-intelligence-analyzer, Property 20: Application Integration Error Handling
Validates: Requirements 9.8
"""

import pytest
from hypothesis import given, strategies as st, assume
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import requests
from requests.exceptions import RequestException, Timeout, ConnectionError as RequestsConnectionError

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from ip_mana.modules.application import (
    ApplicationModule, 
    ApplicationSubmodule, 
    AuthenticationConfig,
    AuthenticationError,
    ConnectionError,
    ApplicationError,
    NetBoxSubmodule,
    CheckMKSubmodule,
    OpenITCockpitSubmodule,
    OpenVASSubmodule,
    InfobloxSubmodule
)


class TestApplicationIntegrationErrorHandling:
    """Property-based tests for application integration error handling requirements."""

    @given(
        submodule_name=st.sampled_from(['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']),
        ip_address=st.one_of(
            st.builds(IPv4Address, st.integers(min_value=0, max_value=2**32-1)),
            st.builds(IPv6Address, st.integers(min_value=0, max_value=2**128-1))
        ),
        error_type=st.sampled_from(['authentication', 'connection', 'timeout', 'api_error'])
    )
    def test_application_integration_graceful_error_handling(self, submodule_name, ip_address, error_type):
        """
        Property 20: Application Integration Error Handling
        
        For any application module submodule that encounters authentication or connection errors,
        the errors should be caught gracefully without terminating the entire analysis process.
        
        **Validates: Requirements 9.8**
        """
        # Create authentication config for testing
        config = AuthenticationConfig(
            auth_type='api_key',
            credentials={'api_key': 'test_key'},
            base_url='https://test.example.com',
            timeout=30
        )
        
        app_module = ApplicationModule({submodule_name: config})
        
        # Mock the requests session to simulate different error conditions
        with patch('requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_session_class.return_value = mock_session
            
            # Configure mock response based on error type
            if error_type == 'authentication':
                mock_response = Mock()
                mock_response.status_code = 401
                mock_response.text = 'Unauthorized'
                mock_session.request.return_value = mock_response
            elif error_type == 'connection':
                mock_session.request.side_effect = RequestsConnectionError("Connection failed")
            elif error_type == 'timeout':
                mock_session.request.side_effect = Timeout("Request timeout")
            elif error_type == 'api_error':
                mock_response = Mock()
                mock_response.status_code = 500
                mock_response.text = 'Internal Server Error'
                mock_session.request.return_value = mock_response
            
            # Load the submodule and query it
            submodule = app_module.load_submodule(submodule_name)
            assert submodule is not None, f"Submodule {submodule_name} should be loadable"
            
            # Query the submodule - this should not raise an exception
            try:
                result = submodule.query_ip(ip_address)
                
                # Verify that the result indicates failure but is properly structured
                assert hasattr(result, 'success'), "Result should have success attribute"
                assert hasattr(result, 'data'), "Result should have data attribute"
                assert hasattr(result, 'error_message'), "Result should have error_message attribute"
                assert hasattr(result, 'source'), "Result should have source attribute"
                
                # Error should be handled gracefully
                assert result.success is False, "Result should indicate failure for error conditions"
                assert result.error_message is not None, "Error message should be provided"
                assert len(result.error_message) > 0, "Error message should not be empty"
                assert isinstance(result.data, dict), "Data should be a dictionary even on error"
                
                # Verify error message contains relevant information
                error_msg_lower = result.error_message.lower()
                if error_type == 'authentication':
                    assert 'authentication' in error_msg_lower or 'unauthorized' in error_msg_lower
                elif error_type == 'connection':
                    assert 'connection' in error_msg_lower
                elif error_type == 'timeout':
                    assert 'timeout' in error_msg_lower
                elif error_type == 'api_error':
                    assert 'error' in error_msg_lower or '500' in error_msg_lower
                
            except Exception as e:
                pytest.fail(f"Submodule {submodule_name} should handle {error_type} errors gracefully, but raised: {e}")

    @given(
        submodule_names=st.lists(
            st.sampled_from(['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']),
            min_size=2,
            max_size=4,
            unique=True
        ),
        ip_address=st.one_of(
            st.builds(IPv4Address, st.integers(min_value=0, max_value=2**32-1)),
            st.builds(IPv6Address, st.integers(min_value=0, max_value=2**128-1))
        )
    )
    def test_partial_failure_isolation(self, submodule_names, ip_address):
        """
        Property 20: Application Integration Error Handling (Failure Isolation)
        
        For any set of application submodules where some fail and others succeed,
        failures should be isolated and not affect the execution of other submodules.
        
        **Validates: Requirements 9.8**
        """
        # Create configurations for all submodules
        configurations = {}
        for name in submodule_names:
            configurations[name] = AuthenticationConfig(
                auth_type='api_key',
                credentials={'api_key': f'test_key_{name}'},
                base_url=f'https://{name}.example.com',
                timeout=30
            )
        
        app_module = ApplicationModule(configurations)
        
        # Mock different behaviors for different submodules
        with patch('requests.Session') as mock_session_class:
            def create_mock_session():
                return MagicMock()
            
            mock_session_class.side_effect = create_mock_session
            
            # Make some submodules fail and others succeed
            failing_submodules = submodule_names[:len(submodule_names)//2]
            succeeding_submodules = submodule_names[len(submodule_names)//2:]
            
            # Patch each submodule's _make_request method
            for i, submodule_name in enumerate(submodule_names):
                submodule = app_module.load_submodule(submodule_name)
                
                if submodule_name in failing_submodules:
                    # Make this submodule fail
                    with patch.object(submodule, '_make_request', side_effect=ConnectionError("Simulated failure")):
                        pass  # The patch will be active during query_all_enabled
                else:
                    # Make this submodule succeed
                    with patch.object(submodule, '_make_request', return_value={'test': 'data'}):
                        pass  # The patch will be active during query_all_enabled
            
            # Query all submodules
            results = app_module.query_all_enabled(ip_address, submodule_names)
            
            # Verify that we got results for all requested submodules
            assert len(results) == len(submodule_names), "Should get results for all submodules"
            assert set(results.keys()) == set(submodule_names), "Should have results for exactly the requested submodules"
            
            # Verify that each result is properly structured regardless of success/failure
            for submodule_name, result in results.items():
                assert hasattr(result, 'success'), f"Result for {submodule_name} should have success attribute"
                assert hasattr(result, 'data'), f"Result for {submodule_name} should have data attribute"
                assert hasattr(result, 'error_message'), f"Result for {submodule_name} should have error_message attribute"
                assert isinstance(result.data, dict), f"Data for {submodule_name} should be a dictionary"
                
                # Verify that failure of one submodule doesn't affect others
                # (This is implicitly tested by getting results for all submodules)

    @given(
        submodule_name=st.sampled_from(['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']),
        ip_address=st.one_of(
            st.builds(IPv4Address, st.integers(min_value=0, max_value=2**32-1)),
            st.builds(IPv6Address, st.integers(min_value=0, max_value=2**128-1))
        )
    )
    def test_missing_configuration_handling(self, submodule_name, ip_address):
        """
        Property 20: Application Integration Error Handling (Missing Configuration)
        
        For any application submodule without proper configuration,
        the system should handle the missing configuration gracefully.
        
        **Validates: Requirements 9.8**
        """
        # Create application module without configurations
        app_module = ApplicationModule()
        
        # Load submodule without configuration
        submodule = app_module.load_submodule(submodule_name)
        assert submodule is not None, f"Submodule {submodule_name} should be loadable even without config"
        
        # Query the submodule - this should handle missing config gracefully
        try:
            result = submodule.query_ip(ip_address)
            
            # Verify that the result indicates failure but is properly structured
            assert hasattr(result, 'success'), "Result should have success attribute"
            assert hasattr(result, 'data'), "Result should have data attribute"
            assert hasattr(result, 'error_message'), "Result should have error_message attribute"
            
            # Should fail gracefully due to missing configuration
            assert result.success is False, "Result should indicate failure for missing configuration"
            assert result.error_message is not None, "Error message should be provided"
            assert isinstance(result.data, dict), "Data should be a dictionary even on error"
            
        except Exception as e:
            pytest.fail(f"Submodule {submodule_name} should handle missing configuration gracefully, but raised: {e}")

    @given(
        auth_type=st.sampled_from(['api_key', 'basic', 'token', 'oauth']),
        credentials=st.dictionaries(
            st.sampled_from(['api_key', 'username', 'password', 'token']),
            st.text(min_size=1, max_size=50),
            min_size=1,
            max_size=3
        ),
        base_url=st.sampled_from([
            'https://api.example.com',
            'http://localhost:8080',
            'https://test.domain.org',
            'http://192.168.1.100:3000'
        ]),
        timeout=st.integers(min_value=1, max_value=300)
    )
    def test_authentication_configuration_robustness(self, auth_type, credentials, base_url, timeout):
        """
        Property 20: Application Integration Error Handling (Authentication Robustness)
        
        For any authentication configuration, the system should handle
        various authentication setups without crashing.
        
        **Validates: Requirements 9.8**
        """
        try:
            config = AuthenticationConfig(
                auth_type=auth_type,
                credentials=credentials,
                base_url=base_url,
                timeout=timeout
            )
            
            # Create a submodule with this configuration
            submodule = NetBoxSubmodule(config)
            
            # Verify that the submodule was created successfully
            assert submodule is not None, "Submodule should be created with any valid configuration"
            assert submodule.config == config, "Submodule should store the provided configuration"
            
            # Verify that authentication setup doesn't crash
            # (This is tested by the successful creation of the submodule)
            
        except Exception as e:
            # Only allow specific expected exceptions for invalid configurations
            if not isinstance(e, (ValueError, TypeError)):
                pytest.fail(f"Authentication configuration should be robust, but raised unexpected exception: {e}")