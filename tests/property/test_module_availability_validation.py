"""
Property-based tests for module availability validation.

Feature: ip-intelligence-analyzer, Property 9: Module Availability Validation
Validates: Requirements 5.4
"""

from hypothesis import given, strategies as st, settings
from pathlib import Path
import tempfile
import json

from src.ip_mana.analyzer import IPAnalyzer
from src.ip_mana.config import Config


# Strategy for generating module names
@st.composite
def module_names_strategy(draw):
    """Generate lists of module names (valid and invalid)."""
    all_modules = [
        'classification', 'local_info', 'internet_info',
        'netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox'
    ]
    invalid_modules = ['invalid_module', 'nonexistent', 'fake_module']

    # Mix of valid and invalid modules
    valid_count = draw(st.integers(min_value=0, max_value=len(all_modules)))
    invalid_count = draw(st.integers(min_value=0, max_value=3))

    valid_selected = draw(st.lists(
        st.sampled_from(all_modules),
        min_size=valid_count,
        max_size=valid_count,
        unique=True
    ))

    invalid_selected = draw(st.lists(
        st.sampled_from(invalid_modules),
        min_size=invalid_count,
        max_size=invalid_count,
        unique=True
    ))

    return valid_selected + invalid_selected


@settings(max_examples=100, deadline=None)
@given(module_names=module_names_strategy())
def test_module_availability_validation_property(module_names):
    """
    Property 9: Module Availability Validation

    For any requested module that is not available or properly configured,
    the application should detect the unavailability before attempting execution
    and handle it gracefully.

    Validates: Requirements 5.4
    """
    # Create a minimal config
    config = Config()

    # Create analyzer (without credential file for testing)
    analyzer = IPAnalyzer(config=config)

    # Validate module availability
    availability = analyzer.validate_module_availability(module_names)

    # Property 1: All requested modules should have an availability status
    assert len(availability) == len(module_names), \
        "All requested modules should have availability status"

    # Property 2: Core modules should always be available
    core_modules = ['classification', 'local_info', 'internet_info']
    for module in module_names:
        if module in core_modules:
            assert availability.get(module, False) is True, \
                f"Core module {module} should always be available"

    # Property 3: Invalid module names should be marked as unavailable
    valid_modules = [
        'classification', 'local_info', 'internet_info',
        'netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox'
    ]
    for module in module_names:
        if module not in valid_modules:
            # Invalid modules should either not be in availability dict
            # or be marked as False
            if module in availability:
                assert availability[module] is False, \
                    f"Invalid module {module} should be marked unavailable"

    # Property 4: Availability check should not raise exceptions
    # (This is implicitly tested by the test not failing)

    # Property 5: Application submodules without credentials should be detectable
    app_submodules = ['netbox', 'checkmk', 'openitcockpit', 'openvas', 'infoblox']
    for module in module_names:
        if module in app_submodules:
            # Without credentials, these may or may not be available
            # but the check should complete without error
            assert module in availability or module not in valid_modules, \
                f"Application submodule {module} should have availability status"


def test_module_availability_with_all_core_modules():
    """Test that all core modules are always available."""
    config = Config()
    analyzer = IPAnalyzer(config=config)

    core_modules = ['classification', 'local_info', 'internet_info']
    availability = analyzer.validate_module_availability(core_modules)

    for module in core_modules:
        assert availability[module] is True, \
            f"Core module {module} should be available"


def test_module_availability_with_invalid_modules():
    """Test that invalid modules are handled gracefully."""
    config = Config()
    analyzer = IPAnalyzer(config=config)

    invalid_modules = ['invalid_module', 'nonexistent', 'fake_module']
    availability = analyzer.validate_module_availability(invalid_modules)

    # Invalid modules should either not appear in results or be marked False
    for module in invalid_modules:
        if module in availability:
            assert availability[module] is False, \
                f"Invalid module {module} should be marked unavailable"


def test_module_availability_empty_list():
    """Test module availability with empty list."""
    config = Config()
    analyzer = IPAnalyzer(config=config)

    availability = analyzer.validate_module_availability([])

    assert isinstance(availability, dict), \
        "Availability check should return a dictionary"
    assert len(availability) == 0, \
        "Empty module list should return empty availability dict"


def test_get_available_modules():
    """Test that get_available_modules returns expected modules."""
    config = Config()
    analyzer = IPAnalyzer(config=config)

    available = analyzer.get_available_modules()

    # Core modules should always be in the list
    assert 'classification' in available
    assert 'local_info' in available
    assert 'internet_info' in available

    # Result should be a list
    assert isinstance(available, list)

    # All items should be strings
    assert all(isinstance(m, str) for m in available)


def test_module_availability_with_credentials():
    """Test module availability when credentials are provided."""
    # Create a temporary credential file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        credentials = {
            "netbox": {
                "enabled": True,
                "base_url": "http://localhost:8000",
                "authentication": {
                    "method": "api_token",
                    "api_token": "test_token"
                }
            },
            "checkmk": {
                "enabled": False,
                "base_url": "http://localhost:5000",
                "authentication": {
                    "method": "basic_auth",
                    "username": "test",
                    "password": "test"
                }
            }
        }
        json.dump(credentials, f)
        credential_file = f.name

    try:
        config = Config()
        analyzer = IPAnalyzer(config=config, credential_file=credential_file)

        # Check availability of application modules
        app_modules = ['netbox', 'checkmk']
        availability = analyzer.validate_module_availability(app_modules)

        # Both should have availability status
        assert 'netbox' in availability
        assert 'checkmk' in availability

    finally:
        # Clean up
        Path(credential_file).unlink(missing_ok=True)
