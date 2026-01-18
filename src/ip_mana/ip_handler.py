"""
IP Address handling and validation for IP Intelligence Analyzer.

This module provides comprehensive IP address validation, normalization,
and network calculation utilities supporting both IPv4 and IPv6.
"""

from ipaddress import AddressValueError, IPv4Address, IPv6Address, ip_address, ip_network
from typing import Union, Optional, List


class IPAddressValidationError(Exception):
    """Raised when IP address validation fails."""


class IPAddressHandler:
    """
    Handles IP address validation, normalization, and network operations.

    Supports both IPv4 and IPv6 addresses with comprehensive validation
    and utility methods for network calculations.
    """

    @staticmethod
    def validate_ip(ip_str: str) -> Union[IPv4Address, IPv6Address]:
        """
        Validate and parse an IP address string.

        Args:
            ip_str: String representation of IP address

        Returns:
            IPv4Address or IPv6Address object

        Raises:
            IPAddressValidationError: If the IP address format is invalid
        """
        if not ip_str or not isinstance(ip_str, str):
            raise IPAddressValidationError("IP address must be a non-empty string")

        # Strip whitespace
        ip_str = ip_str.strip()

        if not ip_str:
            raise IPAddressValidationError(
                "IP address cannot be empty or whitespace only")

        try:
            return ip_address(ip_str)
        except (AddressValueError, ValueError) as e:
            raise IPAddressValidationError(
                f"Invalid IP address format '{ip_str}': {str(e)}")

    @staticmethod
    def get_ip_version(ip: Union[IPv4Address, IPv6Address, str]) -> int:
        """
        Get the IP version (4 or 6) of an IP address.

        Args:
            ip: IP address object or string

        Returns:
            4 for IPv4, 6 for IPv6

        Raises:
            IPAddressValidationError: If the IP address is invalid
        """
        if isinstance(ip, str):
            ip = IPAddressHandler.validate_ip(ip)

        return ip.version

    @staticmethod
    def normalize_ip(ip_str: str) -> str:
        """
        Normalize an IP address to its canonical string representation.

        Args:
            ip_str: String representation of IP address

        Returns:
            Normalized IP address string

        Raises:
            IPAddressValidationError: If the IP address is invalid
        """
        ip_obj = IPAddressHandler.validate_ip(ip_str)
        return str(ip_obj)

    @staticmethod
    def is_in_subnet(ip: Union[str, IPv4Address, IPv6Address],
                     subnet: str) -> bool:
        """
        Check if an IP address belongs to a specific subnet.

        Args:
            ip: IP address to check (string or IP object)
            subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")

        Returns:
            True if IP is in subnet, False otherwise

        Raises:
            IPAddressValidationError: If IP or subnet format is invalid
        """
        if isinstance(ip, str):
            ip = IPAddressHandler.validate_ip(ip)

        try:
            network = ip_network(subnet, strict=False)
        except (AddressValueError, ValueError) as e:
            raise IPAddressValidationError(
                f"Invalid subnet format '{subnet}': {str(e)}")

        # Check version compatibility
        if ip.version != network.version:
            return False

        return ip in network

    @staticmethod
    def get_network_info(ip: Union[str, IPv4Address, IPv6Address],
                         prefix_length: Optional[int] = None) -> dict:
        """
        Get network information for an IP address.

        Args:
            ip: IP address (string or IP object)
            prefix_length: Network prefix length (optional)

        Returns:
            Dictionary containing network information

        Raises:
            IPAddressValidationError: If IP address is invalid
        """
        if isinstance(ip, str):
            ip_obj = IPAddressHandler.validate_ip(ip)
        else:
            ip_obj = ip

        result = {
            'ip_address': str(ip_obj),
            'version': ip_obj.version,
            'is_private': ip_obj.is_private,
            'is_global': ip_obj.is_global,
            'is_multicast': ip_obj.is_multicast,
            'is_loopback': ip_obj.is_loopback,
            'is_link_local': ip_obj.is_link_local,
        }

        # Add version-specific properties
        if ip_obj.version == 4:
            result.update({
                'is_reserved': ip_obj.is_reserved,
                'is_unspecified': ip_obj.is_unspecified,
            })
        elif ip_obj.version == 6:
            result.update({
                'is_reserved': ip_obj.is_reserved,
                'is_unspecified': ip_obj.is_unspecified,
                'is_site_local': ip_obj.is_site_local,
            })

        # Add network information if prefix length is provided
        if prefix_length is not None:
            try:
                if ip_obj.version == 4:
                    network = ip_network(f"{ip_obj}/{prefix_length}", strict=False)
                else:
                    network = ip_network(f"{ip_obj}/{prefix_length}", strict=False)

                result.update({
                    'network': str(network),
                    'network_address': str(network.network_address),
                    'broadcast_address': str(network.broadcast_address) if network.version == 4 else None,
                    'netmask': str(network.netmask) if network.version == 4 else None,
                    'hostmask': str(network.hostmask) if network.version == 4 else None,
                    'num_addresses': network.num_addresses,
                })
            except AddressValueError as e:
                raise IPAddressValidationError(
                    f"Invalid prefix length {prefix_length}: {str(e)}")

        return result

    @staticmethod
    def get_common_subnets(ip: Union[str, IPv4Address, IPv6Address]) -> List[str]:
        """
        Get list of common subnet sizes that contain the IP address.

        Args:
            ip: IP address (string or IP object)

        Returns:
            List of subnet strings in CIDR notation

        Raises:
            IPAddressValidationError: If IP address is invalid
        """
        if isinstance(ip, str):
            ip_obj = IPAddressHandler.validate_ip(ip)
        else:
            ip_obj = ip

        subnets = []

        if ip_obj.version == 4:
            # Common IPv4 subnet sizes
            common_prefixes = [8, 16, 24, 25, 26, 27, 28, 29, 30]
        else:
            # Common IPv6 subnet sizes
            common_prefixes = [32, 48, 56, 64, 96, 112, 120, 124, 126, 127]

        for prefix in common_prefixes:
            try:
                network = ip_network(f"{ip_obj}/{prefix}", strict=False)
                subnets.append(str(network))
            except AddressValueError:
                # Skip invalid combinations
                continue

        return subnets

    @staticmethod
    def compare_ips(ip1: Union[str, IPv4Address, IPv6Address],
                    ip2: Union[str, IPv4Address, IPv6Address]) -> dict:
        """
        Compare two IP addresses and return relationship information.

        Args:
            ip1: First IP address
            ip2: Second IP address

        Returns:
            Dictionary with comparison results

        Raises:
            IPAddressValidationError: If either IP address is invalid
        """
        if isinstance(ip1, str):
            ip1_obj = IPAddressHandler.validate_ip(ip1)
        else:
            ip1_obj = ip1

        if isinstance(ip2, str):
            ip2_obj = IPAddressHandler.validate_ip(ip2)
        else:
            ip2_obj = ip2

        return {
            'same_version': ip1_obj.version == ip2_obj.version,
            'equal': ip1_obj == ip2_obj,
            'ip1_version': ip1_obj.version,
            'ip2_version': ip2_obj.version,
            'ip1_str': str(ip1_obj),
            'ip2_str': str(ip2_obj),
        }

    @staticmethod
    def is_valid_ip_format(ip_str: str) -> bool:
        """
        Check if a string is a valid IP address format without raising exceptions.

        Args:
            ip_str: String to validate

        Returns:
            True if valid IP format, False otherwise
        """
        try:
            IPAddressHandler.validate_ip(ip_str)
            return True
        except IPAddressValidationError:
            return False
