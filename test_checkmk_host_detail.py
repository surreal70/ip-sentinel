#!/usr/bin/env python3
"""Test script to see detailed host structure."""

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

# Get a specific host detail
url = f"{BASE_URL}/check_mk/api/1.0/objects/host/wrk-cob-vm-0800"
print(f"Getting host details from: {url}\n")

response = requests.get(
    url,
    auth=HTTPBasicAuth(USERNAME, PASSWORD),
    headers={'Accept': 'application/json'},
    verify=VERIFY_SSL,
    timeout=30
)

if response.status_code == 200:
    data = response.json()
    print(json.dumps(data, indent=2))
else:
    print(f"Error: {response.status_code}")
    print(response.text)
