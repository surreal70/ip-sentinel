#!/usr/bin/env python3
"""
Live test script for CheckMK integration.

Tests the CheckMK submodule with real credentials against the actual CheckMK instance.
"""

import sys
import json
from ipaddress import IPv4Address
from src.ip_mana.modules.application import (
    CheckMKSubmodule,
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
    
    checkmk_config = cred_manager.get_submodule_config('checkmk')
    if checkmk_config:
        print(f"\nCheckMK Configuration:")
        print(f"  Base URL: {checkmk_config.base_url}")
        print(f"  Auth Type: {checkmk_config.auth_type}")
        print(f"  Timeout: {checkmk_config.timeout}")
        print(f"  Username: {checkmk_config.credentials.get('username', 'N/A')}")
        print(f"  Password: {'*' * len(checkmk_config.credentials.get('password', ''))}")
    else:
        print("ERROR: Could not load CheckMK configuration!")
        return None
    
    return checkmk_config


def test_checkmk_direct(config, test_ips):
    """Test CheckMK submodule directly."""
    print_section("Testing CheckMK Submodule Directly")
    
    submodule = CheckMKSubmodule(config)
    
    for ip_str in test_ips:
        print(f"\n--- Testing IP: {ip_str} ---")
        try:
            ip = IPv4Address(ip_str)
            result = submodule.query_ip(ip)
            print_result(result)
            
            # Print summary
            if result.success and result.data:
                print("\nSummary:")
                print(f"  Hosts found: {len(result.data.get('hosts', []))}")
                print(f"  Services found: {len(result.data.get('services', []))}")
                print(f"  Host status records: {len(result.data.get('host_status', []))}")
                print(f"  Alerts found: {len(result.data.get('alerts', []))}")
                print(f"  Notifications found: {len(result.data.get('notifications', []))}")
                print(f"  Performance data records: {len(result.data.get('performance_data', []))}")
                print(f"  Check results: {len(result.data.get('check_results', []))}")
                
                # Print host details if found
                if result.data.get('hosts'):
                    print("\nHost Details:")
                    for host in result.data['hosts']:
                        host_id = host.get('id', 'Unknown')
                        host_attrs = host.get('extensions', {}).get('attributes', {})
                        print(f"  - Host: {host_id}")
                        print(f"    IP: {host_attrs.get('ipaddress', 'N/A')}")
                        print(f"    Alias: {host_attrs.get('alias', 'N/A')}")
                        print(f"    Site: {host_attrs.get('site', 'N/A')}")
                
                # Print service summary if found
                if result.data.get('services'):
                    print("\nService Summary:")
                    for service in result.data['services'][:5]:  # Show first 5
                        service_id = service.get('id', 'Unknown')
                        service_ext = service.get('extensions', {})
                        state = service_ext.get('state', 'N/A')
                        output = service_ext.get('plugin_output', 'N/A')
                        print(f"  - {service_id}: State={state}, Output={output[:60]}...")
                    
                    if len(result.data['services']) > 5:
                        print(f"  ... and {len(result.data['services']) - 5} more services")
        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()


def test_application_module(test_ips):
    """Test through ApplicationModule."""
    print_section("Testing Through ApplicationModule")
    
    app_module = ApplicationModule("config/app_credentials.json")
    
    print(f"Available submodules: {app_module.get_available_submodules()}")
    print(f"Enabled submodules: {app_module.get_enabled_submodules()}")
    
    # Load CheckMK submodule
    checkmk = app_module.load_submodule('checkmk')
    if checkmk:
        print("\nCheckMK submodule loaded successfully")
        
        # Test with first IP
        test_ip = IPv4Address(test_ips[0])
        print(f"\nQuerying IP: {test_ip}")
        result = checkmk.query_ip(test_ip)
        print_result(result)
    else:
        print("ERROR: Could not load CheckMK submodule!")


def main():
    """Main test function."""
    print_section("CheckMK Live Integration Test")
    print("Testing CheckMK integration with real credentials")
    print("CheckMK Instance: https://checkmk.adminsend.local")
    
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
    
    # Test 2: Direct CheckMK submodule test
    test_checkmk_direct(config, test_ips)
    
    # Test 3: Through ApplicationModule
    test_application_module(test_ips)
    
    print_section("Test Complete")


if __name__ == '__main__':
    main()
