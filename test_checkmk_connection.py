#!/usr/bin/env python3
"""
Simple CheckMK connection test to verify API access and list available hosts.
"""

import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
base_url = "https://checkmk.adminsend.local/AdminsEnd"
username = "monitor"
password = "Monitor1234!"

print("=" * 80)
print("CheckMK Connection Test")
print("=" * 80)
print(f"Base URL: {base_url}")
print(f"Username: {username}")
print()

# Test 1: Get all hosts
print("Test 1: Fetching all hosts from CheckMK")
print("-" * 80)

try:
    url = f"{base_url}/check_mk/api/1.0/domain-types/host_config/collections/all"
    response = requests.get(
        url,
        auth=HTTPBasicAuth(username, password),
        verify=False,
        timeout=30
    )
    
    print(f"URL: {url}")
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        hosts = data.get('value', [])
        print(f"✓ Success! Found {len(hosts)} hosts")
        
        if hosts:
            print("\nHost List:")
            for host in hosts[:10]:  # Show first 10
                host_id = host.get('id', 'Unknown')
                host_attrs = host.get('extensions', {}).get('attributes', {})
                ip = host_attrs.get('ipaddress', 'N/A')
                alias = host_attrs.get('alias', 'N/A')
                print(f"  - {host_id}: IP={ip}, Alias={alias}")
            
            if len(hosts) > 10:
                print(f"  ... and {len(hosts) - 10} more hosts")
            
            # Show all IPs for matching
            print("\nAll monitored IPs:")
            ips = set()
            for host in hosts:
                host_attrs = host.get('extensions', {}).get('attributes', {})
                ip = host_attrs.get('ipaddress')
                if ip:
                    ips.add(ip)
            
            for ip in sorted(ips):
                print(f"  - {ip}")
        else:
            print("No hosts found in CheckMK")
    else:
        print(f"✗ Failed with status {response.status_code}")
        print(f"Response: {response.text[:500]}")
        
except Exception as e:
    print(f"✗ Error: {e}")

# Test 2: Try to get version info
print("\n" + "=" * 80)
print("Test 2: Getting CheckMK version")
print("-" * 80)

try:
    url = f"{base_url}/check_mk/api/1.0/version"
    response = requests.get(
        url,
        auth=HTTPBasicAuth(username, password),
        verify=False,
        timeout=30
    )
    
    print(f"URL: {url}")
    print(f"Status Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"✓ Success!")
        print(f"Version Info: {json.dumps(data, indent=2)}")
    else:
        print(f"✗ Failed with status {response.status_code}")
        
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "=" * 80)
print("Connection test complete")
print("=" * 80)
