#!/usr/bin/env python3
"""Test script to search for hosts by IP using different methods."""

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

def test_endpoint(url, description, params=None):
    print(f"\n{'='*60}")
    print(f"{description}")
    print(f"URL: {url}")
    if params:
        print(f"Params: {params}")
    print('='*60)
    
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers={'Accept': 'application/json'},
            params=params,
            verify=VERIFY_SSL,
            timeout=30
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            value = data.get('value', [])
            print(f"Results: {len(value)} items")
            if value:
                print(f"\nFirst item:")
                print(json.dumps(value[0], indent=2)[:800])
        else:
            print(f"Error: {response.text[:300]}")
    except Exception as e:
        print(f"Exception: {e}")

# Test 1: Get all hosts and check their structure
test_endpoint(
    f"{BASE_URL}/check_mk/api/1.0/domain-types/host/collections/all",
    "Get all hosts"
)

# Test 2: Try to filter by IP (if supported)
test_endpoint(
    f"{BASE_URL}/check_mk/api/1.0/domain-types/host/collections/all",
    f"Try to filter hosts by IP {TARGET_IP}",
    params={'ipaddress': TARGET_IP}
)

# Test 3: Get services (might include IP info)
test_endpoint(
    f"{BASE_URL}/check_mk/api/1.0/domain-types/service/collections/all",
    "Get all services"
)

# Test 4: Try livestatus query if available
test_endpoint(
    f"{BASE_URL}/check_mk/api/1.0/domain-types/host/actions/query/invoke",
    "Try livestatus query"
)

print("\n" + "="*60)
print("Testing complete")
