"""
Property-based tests for Module 4 access control.

Feature: ip-intelligence-analyzer, Property 8: Module 4 Access Control
Validates: Requirements 5.2, 5.3, 9.7
"""

import pytest
from hypothesis import given, strategies as st, assume
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import Mock, patch
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from ip_mana.modules.application import ApplicationModule, AuthenticationConfig


class TestModule4AccessControl:
    """Property-based tests for Module 4 access control requirements."""

    @given(
        submodule_names=st.lists(
            st.sampled_from(['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']),
            min_size=1,
            max_size=3,
            unique=True
        ),
        ip_address=st.one_of(
            st.builds(IPv4Address, st.integers(min_value=0, max_value=2**32-1)),
            st.builds(IPv6Address, st.integers(min_value=0, max_value=2**128-1))
        )
    )
    def test_module4_requires_explicit_submodule_specification(self, submodule_names, ip_address):
        """
        Property 8: Module 4 Access Control
        
        For any Module 4 execution, each submodule should only execute when explicitly 
        specified via command-line options, and each submodule should require individual specification.
        
        **Validates: Requirements 5.2, 5.3, 9.7**
        """
        # Create application module
        app_module = ApplicationModule()
        
        # Test that submodules are only loaded when explicitly requested
        # Initially, no submodules should be loaded
        assert len(app_module.loaded_submodules) == 0
        
        # Load each submodule explicitly
        loaded_submodules = []
        for submodule_name in submodule_names:
            submodule = app_module.load_submodule(submodule_name)
            assert submodule is not None, f"Submodule {submodule_name} should be loadable"
            loaded_submodules.append(submodule_name)
            
            # Verify that only explicitly loaded submodules are available
            assert submodule_name in app_module.loaded_submodules
            assert len(app_module.loaded_submodules) == len(loaded_submodules)
        
        # Test that query_all_enabled only queries explicitly specified submodules
        results = app_module.query_all_enabled(ip_address, submodule_names)
        
        # Should have results for exactly the specified submodules
        assert set(results.keys()) == set(submodule_names)
        
        # Each result should be an ApplicationResult
        for submodule_name, result in results.items():
            assert hasattr(result, 'success')
            assert hasattr(result, 'data')
            assert hasattr(result, 'source')
            assert result.source == submodule_name

    @given(
        valid_submodules=st.lists(
            st.sampled_from(['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']),
            min_size=0,
            max_size=2,
            unique=True
        ),
        invalid_submodules=st.lists(
            st.text(min_size=1, max_size=20).filter(
                lambda x: x not in ['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']
                and x.isalnum()
            ),
            min_size=1,
            max_size=2,
            unique=True
        )
    )
    def test_module4_validates_submodule_availability(self, valid_submodules, invalid_submodules):
        """
        Property 8: Module 4 Access Control (Availability Validation)
        
        For any requested submodules, the application should validate availability 
        before execution and provide clear feedback when modules are unavailable.
        
        **Validates: Requirements 5.4, 5.5**
        """
        app_module = ApplicationModule()
        
        # Test validation of valid submodules
        if valid_submodules:
            availability = app_module.validate_submodule_availability(valid_submodules)
            for submodule_name in valid_submodules:
                assert availability[submodule_name] is True, f"Valid submodule {submodule_name} should be available"
        
        # Test validation of invalid submodules
        availability = app_module.validate_submodule_availability(invalid_submodules)
        for submodule_name in invalid_submodules:
            assert availability[submodule_name] is False, f"Invalid submodule {submodule_name} should not be available"
        
        # Test that loading invalid submodules raises appropriate errors
        for invalid_name in invalid_submodules:
            with pytest.raises(Exception) as exc_info:
                app_module.load_submodule(invalid_name)
            
            # Should provide clear error message about availability
            error_message = str(exc_info.value).lower()
            assert 'unknown' in error_message or 'available' in error_message

    @given(
        submodule_name=st.sampled_from(['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox'])
    )
    def test_module4_individual_submodule_specification_required(self, submodule_name):
        """
        Property 8: Module 4 Access Control (Individual Specification)
        
        For any Module 4 submodule, it should require individual explicit specification
        and not be automatically included with other submodules.
        
        **Validates: Requirements 5.3, 9.7**
        """
        app_module = ApplicationModule()
        
        # Load one specific submodule
        loaded_submodule = app_module.load_submodule(submodule_name)
        assert loaded_submodule is not None
        
        # Verify that only this specific submodule is loaded
        assert len(app_module.loaded_submodules) == 1
        assert submodule_name in app_module.loaded_submodules
        
        # Verify that other submodules are not automatically loaded
        all_submodules = app_module.get_available_submodules()
        other_submodules = [name for name in all_submodules if name != submodule_name]
        
        for other_name in other_submodules:
            assert other_name not in app_module.loaded_submodules, \
                f"Submodule {other_name} should not be automatically loaded when loading {submodule_name}"

    @given(
        ip_address=st.one_of(
            st.builds(IPv4Address, st.integers(min_value=0, max_value=2**32-1)),
            st.builds(IPv6Address, st.integers(min_value=0, max_value=2**128-1))
        )
    )
    def test_module4_no_default_execution(self, ip_address):
        """
        Property 8: Module 4 Access Control (No Default Execution)
        
        For any IP address analysis, Module 4 submodules should not execute by default
        and should require explicit command-line options to invoke.
        
        **Validates: Requirements 5.1, 5.2**
        """
        app_module = ApplicationModule()
        
        # Test that querying with empty submodule list returns no results
        results = app_module.query_all_enabled(ip_address, [])
        assert len(results) == 0, "No submodules should execute by default"
        
        # Test that no submodules are loaded by default
        assert len(app_module.loaded_submodules) == 0, "No submodules should be loaded by default"
        
        # Test that available submodules exist but are not automatically enabled
        available = app_module.get_available_submodules()
        assert len(available) > 0, "Submodules should be available for explicit loading"
        
        # But none should be loaded without explicit request
        for submodule_name in available:
            assert submodule_name not in app_module.loaded_submodules, \
                f"Submodule {submodule_name} should not be loaded without explicit request"