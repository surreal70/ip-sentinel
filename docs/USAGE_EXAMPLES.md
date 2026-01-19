# IP-Sentinel Usage Examples

This document provides practical examples for using IP Intelligence Analyzer in various scenarios.

## Table of Contents

1. [Basic Usage](#basic-usage)
2. [Output Formats](#output-formats)
3. [Reporting Modes](#reporting-modes)
4. [Module Control](#module-control)
5. [Classification Management](#classification-management)
6. [Application Integration](#application-integration)
7. [Batch Processing](#batch-processing)
8. [Advanced Scenarios](#advanced-scenarios)

## Basic Usage

### Analyze a Single IP Address

```bash
# Analyze a private IP
ip-sentinel 192.168.1.1

# Analyze a public IP
ip-sentinel 8.8.8.8

# Analyze an IPv6 address
ip-sentinel 2001:4860:4860::8888

# Analyze localhost
ip-sentinel 127.0.0.1
```

### Quick Information Lookup

```bash
# Get just the classification
ip-sentinel --dense 192.168.1.1 | grep -A 5 "Classification"

# Check if IP is reachable
ip-sentinel --dense 192.168.1.1 | grep "Reachable"

# Get geolocation for public IP
ip-sentinel --dense 8.8.8.8 | grep -A 10 "Geolocation"
```

## Output Formats

### Human-Readable Output (Default)

```bash
ip-sentinel 192.168.1.1
```

Output:
```
IP Intelligence Analysis Report
================================
IP Address: 192.168.1.1
IP Version: IPv4
Scan Time: 2026-01-18 15:30:45

Classification Results:
- Private Network (RFC 1918)
- Qualifies for: Module 2 (Local Info)

Local Information:
- Reachable: Yes
- MAC Address: 00:11:22:33:44:55
...
```

### JSON Output

```bash
# Output to console
ip-sentinel --json 192.168.1.1

# Save to file
ip-sentinel --json 192.168.1.1 > analysis.json

# Pretty-print JSON
ip-sentinel --json 192.168.1.1 | python -m json.tool

# Extract specific field with jq
ip-sentinel --json 192.168.1.1 | jq '.classifications'
```

### HTML Output

```bash
# Generate HTML report
ip-sentinel --html 192.168.1.1 > report.html

# Open in browser (Linux)
ip-sentinel --html 192.168.1.1 > report.html && xdg-open report.html

# Open in browser (macOS)
ip-sentinel --html 192.168.1.1 > report.html && open report.html

# Open in browser (Windows)
ip-sentinel --html 192.168.1.1 > report.html && start report.html
```

## Reporting Modes

### Dense Mode (Default)

Shows only data where information was collected:

```bash
ip-sentinel --dense 192.168.1.1
# or simply
ip-sentinel 192.168.1.1
```

### Full Mode

Shows all tests, including those with no results:

```bash
ip-sentinel --full 192.168.1.1
```

Output includes:
```
WHOIS Lookup: No results
Geolocation: No results
Spam Lists: No results
...
```

### Full-Error Mode

Includes error messages, timeouts, and failure reasons:

```bash
ip-sentinel --full-err 192.168.1.1
```

Output includes:
```
WHOIS Lookup: Failed - Connection timeout after 30s
Nmap Scan: Error - Permission denied (requires root)
...
```

## Module Control

### Force Internet Module

Analyze private IPs with internet lookups:

```bash
# Force Module 3 for private IP
ip-sentinel --force-internet 192.168.1.1

# Alternative syntax
ip-sentinel --force-module3 192.168.1.1
```

### Disable Specific Modules

```bash
# Only run classification (Module 1)
# Note: Currently not implemented, but planned

# Skip local module
# Note: Currently not implemented, but planned
```

## Classification Management

### List All Classifications

```bash
ip-sentinel --list-classifications
```

### Add Custom Classification

```bash
# Add a custom network range
ip-sentinel --add-classification \
    "Office Network" \
    "10.50.0.0/16" \
    "Corporate office network" \
    "module2,module3"

# Add DMZ network
ip-sentinel --add-classification \
    "DMZ" \
    "172.16.100.0/24" \
    "Demilitarized zone" \
    "module2,module3,module4"
```

### Delete Classification

```bash
ip-sentinel --delete-classification "Office Network"
```

### Modify Classification

```bash
# Delete old, add new
ip-sentinel --delete-classification "Office Network"
ip-sentinel --add-classification \
    "Office Network" \
    "10.50.0.0/15" \
    "Expanded office network" \
    "module2,module3"
```

## Application Integration

### NetBox IPAM Integration

```bash
# Query NetBox for IP information
ip-sentinel --netbox 192.168.1.100

# Combine with other output formats
ip-sentinel --netbox --json 192.168.1.100 > netbox-report.json
```

### CheckMK Monitoring Integration

```bash
# Query CheckMK for monitoring data
ip-sentinel --checkmk 192.168.1.100

# Full error mode to see connection issues
ip-sentinel --checkmk --full-err 192.168.1.100
```

### OpenVAS Vulnerability Scanner Integration

```bash
# Query OpenVAS for vulnerability data
ip-sentinel --openvas 192.168.1.100

# Combine with full mode
ip-sentinel --openvas --full 192.168.1.100
```

### Multiple Application Modules

```bash
# Query all application modules
ip-sentinel --netbox --checkmk --openvas 192.168.1.100

# With custom credentials file
ip-sentinel --credentials /etc/ip-sentinel/prod-creds.json \
    --netbox --checkmk --openvas \
    192.168.1.100
```

## Batch Processing

### Analyze Multiple IPs

```bash
# Simple loop
for ip in 192.168.1.{1..10}; do
    echo "Analyzing $ip..."
    ip-sentinel --dense $ip
done

# Save each to separate file
for ip in 192.168.1.{1..10}; do
    ip-sentinel --json $ip > "analysis-${ip}.json"
done

# From file
while read ip; do
    ip-sentinel --dense $ip
done < ip-list.txt
```

### Parallel Processing

```bash
# Using GNU parallel
cat ip-list.txt | parallel -j 4 ip-sentinel --json {} > results.json

# Using xargs
cat ip-list.txt | xargs -P 4 -I {} ip-sentinel --dense {}
```

### Batch Analysis Script

```bash
#!/bin/bash
# batch-analyze.sh

OUTPUT_DIR="./analysis-results"
mkdir -p "$OUTPUT_DIR"

while read ip; do
    echo "Analyzing $ip..."
    timestamp=$(date +%Y%m%d-%H%M%S)
    ip-sentinel --json --full $ip > "$OUTPUT_DIR/${ip}-${timestamp}.json"
    sleep 1  # Rate limiting
done < "$1"

echo "Analysis complete. Results in $OUTPUT_DIR"
```

Usage:
```bash
chmod +x batch-analyze.sh
./batch-analyze.sh ip-list.txt
```

## Advanced Scenarios

### Network Discovery and Analysis

```bash
#!/bin/bash
# Discover and analyze all hosts in subnet

SUBNET="192.168.1.0/24"

# Discover live hosts
nmap -sn $SUBNET -oG - | grep "Up" | awk '{print $2}' > live-hosts.txt

# Analyze each host
while read ip; do
    echo "=== Analyzing $ip ==="
    ip-sentinel --full $ip
    echo ""
done < live-hosts.txt
```

### Security Audit

```bash
#!/bin/bash
# Security audit script

IP="$1"

echo "Security Audit for $IP"
echo "====================="

# Full analysis with all modules
ip-sentinel --full-err --netbox --checkmk --openvas $IP > audit-report.txt

# Extract security-relevant information
echo ""
echo "Open Ports:"
grep -A 20 "Open Ports" audit-report.txt

echo ""
echo "Vulnerabilities:"
grep -A 50 "OpenVAS" audit-report.txt

echo ""
echo "Reputation:"
grep -A 10 "Reputation" audit-report.txt
```

### Monitoring Integration

```bash
#!/bin/bash
# Monitor IP and alert on changes

IP="$1"
PREVIOUS_SCAN="previous-scan.json"
CURRENT_SCAN="current-scan.json"

# Perform scan
ip-sentinel --json $IP > $CURRENT_SCAN

# Compare with previous scan
if [ -f "$PREVIOUS_SCAN" ]; then
    if ! diff -q $PREVIOUS_SCAN $CURRENT_SCAN > /dev/null; then
        echo "ALERT: Changes detected for $IP"
        diff $PREVIOUS_SCAN $CURRENT_SCAN
        # Send notification (email, Slack, etc.)
    fi
fi

# Save current as previous
cp $CURRENT_SCAN $PREVIOUS_SCAN
```

### Database Queries

```bash
# Analyze and store in custom database
ip-sentinel --database /var/lib/ip-sentinel/production.db 192.168.1.1

# Analyze without storing
ip-sentinel --no-database 192.168.1.1

# Query database directly
sqlite3 /var/lib/ip-sentinel/production.db "SELECT * FROM scans WHERE ip_address='192.168.1.1';"
```

### Custom Output Processing

```bash
# Extract specific information with jq
ip-sentinel --json 8.8.8.8 | jq '{
    ip: .ip_address,
    country: .internet_info.geolocation.country,
    asn: .internet_info.asn_info.asn,
    reputation: .internet_info.reputation_score
}'

# Create CSV from multiple scans
echo "IP,Country,ASN,Reputation" > results.csv
for ip in $(cat ip-list.txt); do
    ip-sentinel --json $ip | jq -r '[
        .ip_address,
        .internet_info.geolocation.country,
        .internet_info.asn_info.asn,
        .internet_info.reputation_score
    ] | @csv' >> results.csv
done
```

### Integration with Other Tools

```bash
# Pipe to other security tools
ip-sentinel --json 192.168.1.1 | security-analyzer

# Use with Ansible
ansible-playbook -i inventory.yml analyze-ips.yml \
    --extra-vars "ip_sentinel_cmd='ip-sentinel --json'"

# Use with Docker
docker run -v $(pwd):/data ip-sentinel --json 192.168.1.1 > /data/result.json
```

## Tips and Best Practices

1. **Use JSON for automation**: Always use `--json` when processing output programmatically
2. **Rate limiting**: Add delays between scans to avoid overwhelming networks/APIs
3. **Error handling**: Use `--full-err` when debugging issues
4. **Database management**: Regularly backup your analysis database
5. **Credentials security**: Never commit credentials files to version control
6. **Network permissions**: Ensure you have authorization to scan networks
7. **Resource usage**: Monitor CPU/memory when running batch analyses
8. **Logging**: Redirect output to log files for audit trails

## Troubleshooting Examples

### Debug Connection Issues

```bash
# Verbose output
ip-sentinel --verbose --full-err 192.168.1.1

# Test specific module
ip-sentinel --netbox --verbose 192.168.1.1

# Check credentials
cat config/app_credentials.json | jq '.netbox'
```

### Performance Testing

```bash
# Time analysis
time ip-sentinel 192.168.1.1

# Profile with different modes
time ip-sentinel --dense 192.168.1.1
time ip-sentinel --full 192.168.1.1
time ip-sentinel --full-err 192.168.1.1
```

### Validate Output

```bash
# Validate JSON output
ip-sentinel --json 192.168.1.1 | python -m json.tool > /dev/null && echo "Valid JSON"

# Check for errors in output
ip-sentinel --full-err 192.168.1.1 | grep -i error

# Verify database storage
ip-sentinel 192.168.1.1
sqlite3 ip_analysis.db "SELECT COUNT(*) FROM scans;"
```

## Additional Resources

- Main documentation: [README.md](../README.md)
- License information: [LICENSE](../LICENSE)
- API documentation: [docs/API.md](API.md) (if available)
- Configuration guide: [docs/CONFIGURATION.md](CONFIGURATION.md) (if available)

---

For more examples and use cases, visit the project repository or open an issue with your specific scenario.
