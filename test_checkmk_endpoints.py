#!/usr/bin/env python3
"""
Diagnostic script to find the correct CheckMK API endpoints.
"""

import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Credentials
base_host = "https://checkmk.adminsend.local"
username = "monitor"
password = "Monitor1234!"

# Common CheckMK site names
site_names = ["", "cmk", "monitoring", "site", "default", "main"]

# Common API paths
api_paths = [
    "/check_mk/api/1.0/version",
    "/{site}/check_mk/api/1.0/version",
    "/api/1.0/version",
    "/{site}/api/1.0/version",
    "/check_mk/webapi.py?action=get_all_hosts",
    "/{site}/check_mk/webapi.py?action=get_all_hosts",
]

print("=" * 80)
print("CheckMK API Endpoint Discovery")
print("=" * 80)
print(f"Host: {base_host}")
print(f"Username: {username}")
print(f"Password: {'*' * len(password)}")
print()

def test_endpoint(url):
    """Test an endpoint and return status."""
    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            verify=False,
            timeout=10
        )
        return response.status_code, response.text[:200]
    except Exception as e:
        return None, str(e)

# Test without site name
print("Testing endpoints without site name:")
print("-" * 80)
for path in api_paths:
    if "{site}" not in path:
        url = f"{base_host}{path}"
        status, text = test_endpoint(url)
        print(f"URL: {url}")
        print(f"Status: {status}")
        if status == 200:
            print(f"Response: {text}")
            print("✓ SUCCESS!")
        print()

# Test with different site names
print("\nTesting endpoints with different site names:")
print("-" * 80)
for site in site_names:
    if not site:
        continue
    print(f"\nSite: {site}")
    for path in api_paths:
        if "{site}" in path:
            url = f"{base_host}{path.format(site=site)}"
            status, text = test_endpoint(url)
            print(f"  URL: {url}")
            print(f"  Status: {status}")
            if status == 200:
                print(f"  Response: {text}")
                print("  ✓ SUCCESS!")

# Try to discover site by checking common URLs
print("\n" + "=" * 80)
print("Trying to discover CheckMK installation:")
print("-" * 80)

common_urls = [
    "/",
    "/cmk/",
    "/monitoring/",
    "/check_mk/",
]

for path in common_urls:
    url = f"{base_host}{path}"
    try:
        response = requests.get(url, verify=False, timeout=10, allow_redirects=True)
        print(f"URL: {url}")
        print(f"Status: {response.status_code}")
        print(f"Final URL: {response.url}")
        if "check_mk" in response.text.lower() or "checkmk" in response.text.lower():
            print("✓ CheckMK installation detected!")
        print()
    except Exception as e:
        print(f"URL: {url}")
        print(f"Error: {e}")
        print()

print("=" * 80)
print("Discovery complete")
print("=" * 80)
