#!/usr/bin/env python3
"""
Live OpenVAS API Integration Test

This script tests the OpenVAS submodule against a real OpenVAS instance
to verify API connectivity, authentication, and data retrieval.

Credentials:
- System: openvas.adminsend.local:9392
- Username: monitor
- Password: Monitor1234!
"""

import sys
import json
from ipaddress import IPv4Address
from src.ip_sentinel.modules.application import (
    OpenVASSubmodule,
    AuthenticationConfig,
    ApplicationModule,
    CredentialManager
)


def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def print_subsection(title):
    """Print a formatted subsection header."""
    print(f"\n{'-' * 80}")
    print(f"  {title}")
    print(f"{'-' * 80}\n")


def test_openvas_connection():
    """Test basic OpenVAS connection and authentication."""
    print_section("OpenVAS Live API Integration Test")
    
    # Test IP addresses
    test_ips = [
        IPv4Address('192.168.143.55'),
        IPv4Address('192.168.143.1'),
        IPv4Address('192.168.141.15'),
        IPv4Address('80.152.228.15'),
        IPv4Address('167.235.220.72')
    ]
    
    print("Test Configuration:")
    print(f"  System: openvas.adminsend.local:9392")
    print(f"  Username: monitor")
    print(f"  Test IPs: {', '.join(str(ip) for ip in test_ips)}")
    
    # Create authentication configuration
    auth_config = AuthenticationConfig(
        auth_type='basic',
        credentials={
            'username': 'monitor',
            'password': 'Monitor1234!'
        },
        base_url='https://openvas.adminsend.local:9392',
        timeout=60,
        verify_ssl=False
    )
    
    print_subsection("Test 1: OpenVAS Submodule Initialization")
    try:
        submodule = OpenVASSubmodule(auth_config)
        print("✓ OpenVAS submodule initialized successfully")
        print(f"  Base URL: {submodule.config.base_url}")
        print(f"  Timeout: {submodule.config.timeout}s")
        print(f"  SSL Verification: {submodule.config.verify_ssl}")
    except Exception as e:
        print(f"✗ Failed to initialize OpenVAS submodule: {e}")
        return False
    
    # Test each IP address
    results = {}
    for idx, test_ip in enumerate(test_ips, 1):
        print_subsection(f"Test {idx + 1}: Query IP Address {test_ip}")
        
        try:
            result = submodule.query_ip(test_ip)
            results[str(test_ip)] = result
            
            if result.success:
                print(f"✓ Successfully queried {test_ip}")
                print(f"  Source: {result.source}")
                
                # Display summary of findings
                data = result.data
                print(f"\n  Data Summary:")
                print(f"    Targets: {len(data.get('targets', []))}")
                print(f"    Tasks: {len(data.get('tasks', []))}")
                print(f"    Reports: {len(data.get('reports', []))}")
                print(f"    Results: {len(data.get('results', []))}")
                print(f"    Vulnerabilities: {len(data.get('vulnerabilities', []))}")
                print(f"    CVE References: {len(data.get('cve_information', []))}")
                print(f"    Scan History Entries: {len(data.get('scan_history', []))}")
                
                # Display severity summary
                severity = data.get('severity_summary', {})
                if any(severity.values()):
                    print(f"\n  Severity Summary:")
                    print(f"    Critical: {severity.get('critical', 0)}")
                    print(f"    High: {severity.get('high', 0)}")
                    print(f"    Medium: {severity.get('medium', 0)}")
                    print(f"    Low: {severity.get('low', 0)}")
                    print(f"    Log: {severity.get('log', 0)}")
                
                # Display target details
                if data.get('targets'):
                    print(f"\n  Target Details:")
                    for target in data['targets'][:3]:  # Show first 3
                        print(f"    - ID: {target.get('id', 'N/A')}")
                        print(f"      Name: {target.get('name', 'N/A')}")
                        print(f"      Hosts: {target.get('hosts', 'N/A')}")
                
                # Display task details
                if data.get('tasks'):
                    print(f"\n  Task Details:")
                    for task in data['tasks'][:3]:  # Show first 3
                        print(f"    - ID: {task.get('id', 'N/A')}")
                        print(f"      Name: {task.get('name', 'N/A')}")
                        print(f"      Status: {task.get('status', 'N/A')}")
                        print(f"      Progress: {task.get('progress', 0)}%")
                
                # Display top vulnerabilities
                if data.get('vulnerabilities'):
                    print(f"\n  Top Vulnerabilities:")
                    sorted_vulns = sorted(
                        data['vulnerabilities'],
                        key=lambda v: v.get('severity', 0),
                        reverse=True
                    )
                    for vuln in sorted_vulns[:5]:  # Show top 5
                        print(f"    - {vuln.get('name', 'Unknown')}")
                        print(f"      Severity: {vuln.get('severity', 0)} ({vuln.get('threat', 'N/A')})")
                        print(f"      Port: {vuln.get('port', 'N/A')}")
                        print(f"      NVT OID: {vuln.get('nvt_oid', 'N/A')}")
                
                # Display CVE information
                if data.get('cve_information'):
                    print(f"\n  CVE References:")
                    for cve in data['cve_information'][:10]:  # Show first 10
                        print(f"    - {cve.get('cve_id', 'N/A')}: {cve.get('vulnerability_name', 'Unknown')}")
                        print(f"      Severity: {cve.get('severity', 0)}")
                
            else:
                print(f"✗ Failed to query {test_ip}")
                print(f"  Error: {result.error_message}")
                
        except Exception as e:
            print(f"✗ Exception while querying {test_ip}: {e}")
            import traceback
            traceback.print_exc()
    
    # Test using ApplicationModule with credential manager
    print_subsection("Test 7: ApplicationModule Integration")
    try:
        app_module = ApplicationModule('config/app_credentials.json')
        
        # Check if OpenVAS is enabled in config
        enabled_submodules = app_module.get_enabled_submodules()
        print(f"Enabled submodules: {', '.join(enabled_submodules)}")
        
        if 'openvas' in enabled_submodules:
            print("✓ OpenVAS is enabled in configuration")
            
            # Query using ApplicationModule
            test_ip = test_ips[0]
            print(f"\nQuerying {test_ip} via ApplicationModule...")
            results_dict = app_module.query_all_enabled(test_ip, ['openvas'])
            
            if 'openvas' in results_dict:
                result = results_dict['openvas']
                if result.success:
                    print(f"✓ Successfully queried via ApplicationModule")
                    print(f"  Vulnerabilities found: {len(result.data.get('vulnerabilities', []))}")
                else:
                    print(f"✗ Query failed: {result.error_message}")
        else:
            print("⚠ OpenVAS is not enabled in config/app_credentials.json")
            print("  To enable, set 'enabled': true in the openvas section")
            
    except Exception as e:
        print(f"✗ ApplicationModule test failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Summary
    print_section("Test Summary")
    
    successful_queries = sum(1 for r in results.values() if r.success)
    total_queries = len(results)
    
    print(f"Total IP addresses tested: {total_queries}")
    print(f"Successful queries: {successful_queries}")
    print(f"Failed queries: {total_queries - successful_queries}")
    
    if successful_queries > 0:
        print("\n✓ OpenVAS integration is working!")
        
        # Aggregate statistics
        total_targets = sum(len(r.data.get('targets', [])) for r in results.values() if r.success)
        total_tasks = sum(len(r.data.get('tasks', [])) for r in results.values() if r.success)
        total_vulns = sum(len(r.data.get('vulnerabilities', [])) for r in results.values() if r.success)
        total_cves = sum(len(r.data.get('cve_information', [])) for r in results.values() if r.success)
        
        print(f"\nAggregate Statistics:")
        print(f"  Total targets found: {total_targets}")
        print(f"  Total tasks found: {total_tasks}")
        print(f"  Total vulnerabilities found: {total_vulns}")
        print(f"  Total CVE references: {total_cves}")
        
        return True
    else:
        print("\n✗ All queries failed. Check OpenVAS connectivity and credentials.")
        return False


if __name__ == '__main__':
    try:
        success = test_openvas_connection()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
