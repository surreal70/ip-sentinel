#!/usr/bin/env python3
"""Test script to see host configuration structure."""

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

# Get a specific host configuration
url = f"{BASE_URL}/check_mk/api/1.0/objects/host_config/wrk-cob-vm-0800"
print(f"Getting host config from: {url}\n")

response = requests.get(
    url,
    auth=HTTPBasicAuth(USERNAME, PASSWORD),
    headers={'Accept': 'application/json'},
    verify=VERIFY_SSL,
    timeout=30
)

if response.status_code == 200:
    data = response.json()
    print(json.dumps(data, indent=2)[:2000])
else:
    print(f"Error: {response.status_code}")
    print(response.text)

# Also try to search for a host with a known IP
print("\n" + "="*60)
print("Searching for host with IP 192.168.143.59")
print("="*60)

# Try to get host by searching
url2 = f"{BASE_URL}/check_mk/api/1.0/domain-types/host_config/collections/all"
response2 = requests.get(
    url2,
    auth=HTTPBasicAuth(USERNAME, PASSWORD),
    headers={'Accept': 'application/json'},
    verify=VERIFY_SSL,
    timeout=30
)

if response2.status_code == 200:
    data2 = response2.json()
    print(f"Total host configs: {len(data2.get('value', []))}")
    if data2.get('value'):
        print(f"\nFirst host config:")
        print(json.dumps(data2['value'][0], indent=2)[:1000])
