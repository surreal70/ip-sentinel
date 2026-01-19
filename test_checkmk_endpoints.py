#!/usr/bin/env python3
"""Test various CheckMK endpoints to find IP addresses."""

import requests
import json
from requests.auth import HTTPBasicAuth

# Configuration
BASE_URL = "https://checkmk.adminsend.local/AdminsEnd"
USERNAME = "monitor"
PASSWORD = "Monitor1234!"
VERIFY_SSL = False
TARGET_IP = "192.168.143.59"

# Disable SSL warnings
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_endpoint(description, url, params=None, method='GET'):
    """Test an endpoint and print results."""
    print(f"\n{'='*60}")
    print(description)
    print(f"URL: {url}")
    if params:
        print(f"Params: {params}")
    print('='*60)
    
    try:
        if method == 'GET':
            response = requests.get(
                url,
                auth=HTTPBasicAuth(USERNAME, PASSWORD),
                headers={'Accept': 'application/json'},
                params=params,
                verify=VERIFY_SSL,
                timeout=30
            )
        else:
            response = requests.post(
                url,
                auth=HTTPBasicAuth(USERNAME, PASSWORD),
                headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
                json=params,
                verify=VERIFY_SSL,
                timeout=30
            )
        
        print(f"Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(json.dumps(data, indent=2)[:2000])
            return data
        else:
            print(f"Error: {response.text[:500]}")
            return None
    except Exception as e:
        print(f"Exception: {e}")
        return None

# Test 1: Get first host with show action
print("\n" + "="*60)
print("TEST 1: Get host with show action")
print("="*60)
data = test_endpoint(
    "Get first host details with show action",
    f"{BASE_URL}/check_mk/api/1.0/objects/host/wrk-cob-vm-0800/actions/show/invoke",
    method='POST'
)

# Test 2: Try to get effective attributes
print("\n" + "="*60)
print("TEST 2: Try effective_attributes parameter")
print("="*60)
data = test_endpoint(
    "Get host with effective_attributes",
    f"{BASE_URL}/check_mk/api/1.0/objects/host/wrk-cob-vm-0800",
    params={'effective_attributes': 'true'}
)

# Test 3: Try the show_host endpoint
print("\n" + "="*60)
print("TEST 3: Try show_host endpoint")
print("="*60)
data = test_endpoint(
    "Show host endpoint",
    f"{BASE_URL}/check_mk/api/1.0/objects/host/wrk-cob-vm-0800/actions/show_host/invoke",
    method='POST'
)

# Test 4: Get all hosts and check if we can find one with our IP in the hostname
print("\n" + "="*60)
print("TEST 4: Search for hostname containing IP pattern")
print("="*60)
response = requests.get(
    f"{BASE_URL}/check_mk/api/1.0/domain-types/host/collections/all",
    auth=HTTPBasicAuth(USERNAME, PASSWORD),
    headers={'Accept': 'application/json'},
    verify=VERIFY_SSL,
    timeout=30
)

if response.status_code == 200:
    hosts = response.json().get('value', [])
    print(f"Total hosts: {len(hosts)}")
    
    # Look for hosts with IP-like patterns in name
    ip_pattern = TARGET_IP.replace('.', '-')
    print(f"\nSearching for hosts with pattern: {ip_pattern}")
    
    for host in hosts:
        host_id = host.get('id', '')
        if TARGET_IP.replace('.', '-') in host_id or TARGET_IP.replace('.', '_') in host_id:
            print(f"  Found potential match: {host_id}")

print("\n" + "="*60)
print("Testing complete")
print("="*60)
