#!/usr/bin/env python3
"""
Live test script for NetBox integration.

Tests the NetBox submodule with real credentials against the actual NetBox instance.
"""

import sys
import json
from ipaddress import IPv4Address
from src.ip_sentinel.modules.application import (
    NetBoxSubmodule,
    ApplicationModule,
    CredentialManager,
    AuthenticationConfig
)


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_result(result):
    """Pretty print an ApplicationResult."""
    print(f"\nSuccess: {result.success}")
    print(f"Source: {result.source}")
    
    if result.error_message:
        print(f"Error: {result.error_message}")
    
    if result.data:
        print("\nData:")
        print(json.dumps(result.data, indent=2, default=str))


def test_credential_manager():
    """Test credential manager loading."""
    print_section("Testing Credential Manager")
    
    cred_manager = CredentialManager("config/app_credentials.json")
    
    print(f"Enabled submodules: {cred_manager.get_enabled_submodules()}")
    
    netbox_config = cred_manager.get_submodule_config('netbox')
    if netbox_config:
        print(f"\nNetBox Configuration:")
        print(f"  Base URL: {netbox_config.base_url}")
        print(f"  Auth Type: {netbox_config.auth_type}")
        print(f"  Timeout: {netbox_config.timeout}")
        print(f"  API Token: {netbox_config.credentials.get('api_key', 'N/A')[:20]}...")
    else:
        print("ERROR: Could not load NetBox configuration!")
        return None
    
    return netbox_config


def test_netbox_direct(config, test_ips):
    """Test NetBox submodule directly."""
    print_section("Testing NetBox Submodule Directly")
    
    submodule = NetBoxSubmodule(config)
    
    for ip_str in test_ips:
        print(f"\n--- Testing IP: {ip_str} ---")
        try:
            ip = IPv4Address(ip_str)
            result = submodule.query_ip(ip)
            print_result(result)
            
            # Print summary
            if result.success and result.data:
                print("\nSummary:")
                print(f"  IP Addresses found: {len(result.data.get('ip_addresses', []))}")
                print(f"  Prefixes found: {len(result.data.get('prefixes', []))}")
                print(f"  Devices found: {len(result.data.get('devices', []))}")
                print(f"  Interfaces found: {len(result.data.get('interfaces', []))}")
                print(f"  VLANs found: {len(result.data.get('vlans', []))}")
                print(f"  VRFs found: {len(result.data.get('vrfs', []))}")
        except Exception as e:
            print(f"ERROR: {e}")


def test_application_module(test_ips):
    """Test through ApplicationModule."""
    print_section("Testing Through ApplicationModule")
    
    app_module = ApplicationModule("config/app_credentials.json")
    
    print(f"Available submodules: {app_module.get_available_submodules()}")
    print(f"Enabled submodules: {app_module.get_enabled_submodules()}")
    
    # Load NetBox submodule
    netbox = app_module.load_submodule('netbox')
    if netbox:
        print("\nNetBox submodule loaded successfully")
        
        # Test with first IP
        test_ip = IPv4Address(test_ips[0])
        print(f"\nQuerying IP: {test_ip}")
        result = netbox.query_ip(test_ip)
        print_result(result)
    else:
        print("ERROR: Could not load NetBox submodule!")


def main():
    """Main test function."""
    print_section("NetBox Live Integration Test")
    print("Testing NetBox integration with real credentials")
    print("NetBox Instance: https://netbox.adminsend.local")
    
    # Test IPs from requirements
    test_ips = [
        "192.168.143.55",
        "192.168.143.1",
        "192.168.141.15",
        "80.152.228.15",
        "167.235.220.72"
    ]
    
    print(f"\nTest IPs: {', '.join(test_ips)}")
    
    # Test 1: Credential Manager
    config = test_credential_manager()
    if not config:
        print("\nERROR: Could not load credentials. Exiting.")
        sys.exit(1)
    
    # Test 2: Direct NetBox submodule test
    test_netbox_direct(config, test_ips)
    
    # Test 3: Through ApplicationModule
    test_application_module(test_ips)
    
    print_section("Test Complete")


if __name__ == '__main__':
    main()
