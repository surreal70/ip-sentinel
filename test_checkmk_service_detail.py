#!/usr/bin/env python3
"""Test getting service details with status."""

import requests
import json
from requests.auth import HTTPBasicAuth
from urllib.parse import quote

# Configuration
BASE_URL = "https://checkmk.adminsend.local/AdminsEnd"
USERNAME = "monitor"
PASSWORD = "Monitor1234!"
VERIFY_SSL = False
HOST_NAME = "srv-adh-vm-0074"
SERVICE_NAME = "Uptime"

# Disable SSL warnings
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Test 1: Try to get service status using show_service action
print("="*60)
print(f"Test 1: Get service '{SERVICE_NAME}' status using show_service")
print("="*60)

url = f"{BASE_URL}/check_mk/api/1.0/objects/host/{HOST_NAME}/actions/show_service/invoke"
params = {'service_description': SERVICE_NAME}

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
    print(json.dumps(data, indent=2)[:2000])
else:
    print(f"Error: {response.text[:500]}")

# Test 2: Try to get service object directly
print("\n" + "="*60)
print(f"Test 2: Get service object directly")
print("="*60)

service_id = f"{HOST_NAME}:{SERVICE_NAME}"
url = f"{BASE_URL}/check_mk/api/1.0/objects/service/{quote(service_id)}"

response = requests.get(
    url,
    auth=HTTPBasicAuth(USERNAME, PASSWORD),
    headers={'Accept': 'application/json'},
    verify=VERIFY_SSL,
    timeout=30
)

print(f"Status: {response.status_code}")
if response.status_code == 200:
    data = response.json()
    print(json.dumps(data, indent=2)[:2000])
else:
    print(f"Error: {response.text[:500]}")

# Test 3: Try to query services with more details
print("\n" + "="*60)
print(f"Test 3: Query all services with columns parameter")
print("="*60)

url = f"{BASE_URL}/check_mk/api/1.0/domain-types/service/collections/all"
params = {
    'host_name': HOST_NAME,
    'columns': ['state', 'plugin_output', 'perf_data']
}

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
    services = data.get('value', [])
    print(f"Total services: {len(services)}")
    if services:
        print("\nFirst service:")
        print(json.dumps(services[0], indent=2)[:1500])
else:
    print(f"Error: {response.text[:500]}")

print("\n" + "="*60)
print("Testing complete")
print("="*60)
