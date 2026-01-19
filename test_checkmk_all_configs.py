#!/usr/bin/env python3
"""Test getting all host configurations."""

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

# Try to get all host configurations with effective_attributes=true
url = f"{BASE_URL}/check_mk/api/1.0/domain-types/host_config/collections/all"
print(f"Getting all host configs from: {url}")
print(f"Looking for IP: {TARGET_IP}\n")

response = requests.get(
    url,
    auth=HTTPBasicAuth(USERNAME, PASSWORD),
    headers={'Accept': 'application/json'},
    params={'effective_attributes': 'true'},  # Try to get effective attributes
    verify=VERIFY_SSL,
    timeout=30
)

print(f"Status: {response.status_code}")

if response.status_code == 200:
    data = response.json()
    hosts = data.get('value', [])
    print(f"Total hosts: {len(hosts)}\n")
    
    if hosts:
        print("First host structure:")
        print(json.dumps(hosts[0], indent=2)[:1500])
        
        # Search for our IP
        print(f"\n{'='*60}")
        print(f"Searching for IP {TARGET_IP}...")
        print('='*60)
        
        for host in hosts:
            host_id = host.get('id', 'unknown')
            extensions = host.get('extensions', {})
            attributes = extensions.get('attributes', {})
            
            # Check various possible IP fields
            ip_address = attributes.get('ipaddress')
            ip_v4 = attributes.get('ipv4address')
            ip_v6 = attributes.get('ipv6address')
            
            if ip_address == TARGET_IP or ip_v4 == TARGET_IP:
                print(f"\n✓ FOUND: Host '{host_id}'")
                print(json.dumps(host, indent=2)[:1000])
                break
        else:
            print(f"\nNo host found with IP {TARGET_IP}")
            print("\nShowing IP addresses of first 5 hosts:")
            for i, host in enumerate(hosts[:5]):
                host_id = host.get('id', 'unknown')
                attrs = host.get('extensions', {}).get('attributes', {})
                ip = attrs.get('ipaddress', attrs.get('ipv4address', 'N/A'))
                print(f"  {host_id}: {ip}")
else:
    print(f"Error: {response.text[:500]}")
