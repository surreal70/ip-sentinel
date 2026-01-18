#!/usr/bin/env python3
"""
OpenVAS API Connection Test

This script explores the OpenVAS API to determine the correct endpoints and authentication method.
"""

import requests
import json
from requests.auth import HTTPBasicAuth
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
BASE_URL = "https://openvas.adminsend.local:9392"
USERNAME = "monitor"
PASSWORD = "Monitor1234!"

def test_endpoint(endpoint, method='GET', params=None):
    """Test a specific API endpoint."""
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    print(f"\nTesting: {method} {url}")
    if params:
        print(f"  Params: {params}")
    
    try:
        response = requests.request(
            method=method,
            url=url,
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            params=params,
            timeout=30,
            verify=False
        )
        
        print(f"  Status Code: {response.status_code}")
        print(f"  Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"  Content Length: {len(response.content)} bytes")
        
        # Try to parse as JSON
        try:
            data = response.json()
            print(f"  JSON Response: {json.dumps(data, indent=2)[:500]}...")
            return True, data
        except:
            print(f"  Raw Response (first 500 chars): {response.text[:500]}")
            return False, response.text
            
    except Exception as e:
        print(f"  Error: {e}")
        return False, None

print("=" * 80)
print("OpenVAS API Connection Test")
print("=" * 80)
print(f"\nBase URL: {BASE_URL}")
print(f"Username: {USERNAME}")

# Test various possible endpoints
endpoints_to_test = [
    # Root endpoints
    "",
    "/",
    
    # GMP (Greenbone Management Protocol) endpoints
    "/gmp",
    "/omp",
    
    # API v1 endpoints (common in modern OpenVAS/GVM)
    "/api/v1/targets",
    "/api/v1/tasks",
    "/api/v1/reports",
    "/api/v1/results",
    
    # API v2 endpoints
    "/api/v2/targets",
    "/api/v2/tasks",
    
    # GSA (Greenbone Security Assistant) endpoints
    "/gsa",
    
    # Legacy endpoints
    "/targets",
    "/tasks",
    "/reports",
    
    # OpenVAS specific
    "/openvas",
    
    # Health/status endpoints
    "/health",
    "/status",
    "/version",
    "/api/version",
]

print("\n" + "=" * 80)
print("Testing Endpoints")
print("=" * 80)

successful_endpoints = []
for endpoint in endpoints_to_test:
    success, data = test_endpoint(endpoint)
    if success:
        successful_endpoints.append((endpoint, data))

print("\n" + "=" * 80)
print("Summary")
print("=" * 80)

if successful_endpoints:
    print(f"\n✓ Found {len(successful_endpoints)} working endpoint(s):")
    for endpoint, data in successful_endpoints:
        print(f"  - {endpoint}")
else:
    print("\n✗ No working JSON endpoints found")
    print("\nThis could mean:")
    print("  1. OpenVAS uses a different API structure (possibly GMP/OMP XML-based)")
    print("  2. The port 9392 might be for a different service")
    print("  3. Authentication method might be different")
    print("  4. API might require specific headers or tokens")

print("\n" + "=" * 80)
print("Additional Information")
print("=" * 80)

# Try to get more info about the service
print("\nTrying to identify the service...")
try:
    response = requests.get(
        BASE_URL,
        auth=HTTPBasicAuth(USERNAME, PASSWORD),
        timeout=10,
        verify=False
    )
    print(f"Server Header: {response.headers.get('Server', 'N/A')}")
    print(f"X-Powered-By: {response.headers.get('X-Powered-By', 'N/A')}")
    
    # Check if it's GMP/OMP (XML-based protocol)
    if 'xml' in response.headers.get('Content-Type', '').lower():
        print("\n⚠ This appears to be an XML-based API (GMP/OMP)")
        print("  OpenVAS/GVM typically uses GMP (Greenbone Management Protocol)")
        print("  which is XML-based, not REST/JSON")
        print("\n  You may need to:")
        print("  1. Use a GMP client library (python-gvm)")
        print("  2. Use the GSA web interface API")
        print("  3. Check if there's a REST API wrapper available")
        
except Exception as e:
    print(f"Error getting service info: {e}")

print("\n" + "=" * 80)
