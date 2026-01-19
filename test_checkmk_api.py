#!/usr/bin/env python3
"""Test script to debug CheckMK API connectivity."""

import requests
import json
from requests.auth import HTTPBasicAuth

# Configuration
BASE_URL = "https://checkmk.adminsend.local/AdminsEnd"
USERNAME = "monitor"
PASSWORD = "Monitor1234!"
VERIFY_SSL = False

# Disable SSL warnings
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_api_endpoint(endpoint, description):
    """Test a specific API endpoint."""
    url = f"{BASE_URL}/{endpoint}"
    print(f"\n{'='*60}")
    print(f"Testing: {description}")
    print(f"URL: {url}")
    print(f"{'='*60}")
    
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            headers={
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            verify=VERIFY_SSL,
            timeout=30
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"\nResponse Data:")
            print(json.dumps(data, indent=2)[:1000])  # First 1000 chars
            
            if 'value' in data:
                print(f"\nNumber of items in 'value': {len(data['value'])}")
                if data['value']:
                    print(f"First item: {json.dumps(data['value'][0], indent=2)[:500]}")
        else:
            print(f"Error Response: {response.text[:500]}")
            
    except Exception as e:
        print(f"Exception: {type(e).__name__}: {e}")

# Test different endpoints
print("CheckMK API Debugging")
print(f"Base URL: {BASE_URL}")
print(f"Username: {USERNAME}")

# Test 1: Get all hosts
test_api_endpoint(
    "check_mk/api/1.0/domain-types/host_config/collections/all",
    "Get all host configurations"
)

# Test 2: Alternative hosts endpoint
test_api_endpoint(
    "check_mk/api/1.0/domain-types/host/collections/all",
    "Get all hosts (alternative endpoint)"
)

# Test 3: Try without check_mk prefix
test_api_endpoint(
    "api/1.0/domain-types/host_config/collections/all",
    "Get hosts without check_mk prefix"
)

print("\n" + "="*60)
print("Testing complete")
