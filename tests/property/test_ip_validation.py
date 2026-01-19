"""
Property-based tests for IP address validation.

Feature: ip-intelligence-analyzer, Property 21: Command-Line Interface Validation
Validates: Requirements 10.1, 10.3
"""

import ipaddress
from ipaddress import IPv4Address, IPv6Address

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src.ip_sentinel.ip_handler import IPAddressHandler, IPAddressValidationError


class TestIPAddressValidation:
    """Property tests for IP address validation functionality."""

    @given(st.ip_addresses(v=4))
    def test_valid_ipv4_addresses_accepted(self, ip):
        """
        Property 21: Command-Line Interface Validation
        For any valid IPv4 address, the application should accept and validate it correctly.
        **Validates: Requirements 10.1, 10.3**
        """
        ip_str = str(ip)

        # Should validate without raising exception
        result = IPAddressHandler.validate_ip(ip_str)

        # Should return IPv4Address object
        assert isinstance(result, IPv4Address)
        assert str(result) == ip_str
        assert result.version == 4

    @given(st.ip_addresses(v=6))
    def test_valid_ipv6_addresses_accepted(self, ip):
        """
        Property 21: Command-Line Interface Validation
        For any valid IPv6 address, the application should accept and validate it correctly.
        **Validates: Requirements 10.1, 10.3**
        """
        ip_str = str(ip)

        # Should validate without raising exception
        result = IPAddressHandler.validate_ip(ip_str)

        # Should return IPv6Address object
        assert isinstance(result, IPv6Address)
        assert str(result) == ip_str
        assert result.version == 6

    @given(st.ip_addresses())
    def test_ip_format_validation_consistency(self, ip):
        """
        Property 21: Command-Line Interface Validation
        For any valid IP address, format validation should be consistent.
        **Validates: Requirements 10.1, 10.3**
        """
        ip_str = str(ip)

        # Both validation methods should agree
        is_valid_format = IPAddressHandler.is_valid_ip_format(ip_str)
        assert is_valid_format is True

        # validate_ip should not raise exception
        result = IPAddressHandler.validate_ip(ip_str)
        assert result is not None
        assert str(result) == ip_str

    @given(st.one_of(
        st.just("not.an.ip"),
        st.just("999.999.999.999"),
        st.just("192.168.1"),
        st.just("192.168.1.1.1"),
        st.just("hello world"),
        st.just("256.1.1.1"),
        st.just("1.1.1.-1"),
        st.just("gggg::1"),
        st.just("::gggg"),
        st.just("1:2:3:4:5:6:7:8:9"),
    ))
    def test_invalid_ip_addresses_rejected(self, invalid_ip):
        """
        Property 21: Command-Line Interface Validation
        For any invalid IP address format, the application should reject it with clear error.
        **Validates: Requirements 10.1, 10.3**
        """
        # Should raise IPAddressValidationError
        with pytest.raises(IPAddressValidationError):
            IPAddressHandler.validate_ip(invalid_ip)

        # is_valid_ip_format should return False
        assert IPAddressHandler.is_valid_ip_format(invalid_ip) is False

    @given(st.one_of(
        st.just(""),
        st.just("   "),
        st.just("\t\n"),
        st.just("  \t  "),
        st.just("\n\n\n"),
    ))
    def test_empty_and_whitespace_rejected(self, empty_or_whitespace):
        """
        Property 21: Command-Line Interface Validation
        For any empty or whitespace-only input, validation should fail with clear error.
        **Validates: Requirements 10.1, 10.3**
        """
        with pytest.raises(IPAddressValidationError) as exc_info:
            IPAddressHandler.validate_ip(empty_or_whitespace)

        # Error message should be descriptive
        error_msg = str(exc_info.value)
        assert "empty" in error_msg.lower() or "whitespace" in error_msg.lower()

    @given(st.none() | st.integers() | st.floats() | st.lists(st.text()))
    def test_non_string_input_rejected(self, non_string_input):
        """
        Property 21: Command-Line Interface Validation
        For any non-string input, validation should fail with clear error.
        **Validates: Requirements 10.1, 10.3**
        """
        with pytest.raises(IPAddressValidationError) as exc_info:
            IPAddressHandler.validate_ip(non_string_input)

        # Error message should indicate string requirement
        error_msg = str(exc_info.value)
        assert "string" in error_msg.lower()

    @given(st.ip_addresses())
    def test_ip_normalization_consistency(self, ip):
        """
        Property 21: Command-Line Interface Validation
        For any valid IP address, normalization should produce consistent results.
        **Validates: Requirements 10.1, 10.3**
        """
        ip_str = str(ip)

        # Normalize the IP
        normalized = IPAddressHandler.normalize_ip(ip_str)

        # Should be valid IP format
        assert IPAddressHandler.is_valid_ip_format(normalized)

        # Normalizing again should produce same result
        normalized_again = IPAddressHandler.normalize_ip(normalized)
        assert normalized == normalized_again

        # Should represent the same IP
        original_obj = IPAddressHandler.validate_ip(ip_str)
        normalized_obj = IPAddressHandler.validate_ip(normalized)
        assert original_obj == normalized_obj

    @given(st.ip_addresses())
    def test_version_detection_accuracy(self, ip):
        """
        Property 21: Command-Line Interface Validation
        For any valid IP address, version detection should be accurate.
        **Validates: Requirements 10.1, 10.3**
        """
        ip_str = str(ip)

        # Get version from handler
        detected_version = IPAddressHandler.get_ip_version(ip_str)

        # Should match the actual IP version
        assert detected_version == ip.version
        assert detected_version in [4, 6]

        # Version should be consistent with object type
        ip_obj = IPAddressHandler.validate_ip(ip_str)
        assert detected_version == ip_obj.version


def _is_valid_ip_string(s):
    """Helper function to check if string is valid IP address."""
    try:
        ipaddress.ip_address(s)
        return True
    except (ipaddress.AddressValueError, TypeError, ValueError):
        return False
