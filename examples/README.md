# IP-Sentinel Batch Processing Examples

This directory contains example scripts demonstrating various batch processing scenarios with IP-Sentinel.

## Available Examples

### 1. Simple Batch Scan (`batch_scan_simple.sh`)

Basic batch scanning example for a single network.

**Features:**
- Scans a single CIDR network
- Sequential processing
- JSON output format
- Simple configuration

**Usage:**
```bash
chmod +x batch_scan_simple.sh
./batch_scan_simple.sh
```

**Configuration:**
Edit the script to change:
- `NETWORK`: The CIDR network to scan (default: `192.168.1.0/24`)
- `OUTPUT_FOLDER`: Where to save results (default: `./scan_results`)
- `OUTPUT_FORMAT`: Output format - `json` or `html` (default: `json`)

---

### 2. Parallel Batch Scan (`batch_scan_parallel.sh`)

Demonstrates parallel processing for faster scanning of large networks.

**Features:**
- Parallel processing using multiple CPU cores
- Configurable reporting mode
- Performance optimized
- Progress tracking

**Usage:**
```bash
chmod +x batch_scan_parallel.sh
./batch_scan_parallel.sh
```

**Configuration:**
Edit the script to change:
- `NETWORK`: The CIDR network to scan (default: `192.168.1.0/24`)
- `OUTPUT_FOLDER`: Where to save results (default: `./parallel_scan_results`)
- `OUTPUT_FORMAT`: Output format - `json` or `html` (default: `json`)
- `REPORTING_MODE`: Verbosity level - `dense`, `full`, or `full-err` (default: `dense`)

**Performance:**
- Sequential: ~5-30 seconds per IP
- Parallel: ~2-10x faster depending on CPU cores

---

### 3. Multiple Networks Scan (`batch_scan_multiple_networks.sh`)

Scans multiple networks in a single run with organized output structure.

**Features:**
- Scans multiple CIDR networks
- Organized output by network and timestamp
- Centralized database for all scans
- Comprehensive summary report
- Optional parallel processing

**Usage:**
```bash
chmod +x batch_scan_multiple_networks.sh
./batch_scan_multiple_networks.sh
```

**Configuration:**
Edit the script to change:
- `NETWORKS`: Array of CIDR networks to scan
- `OUTPUT_BASE`: Base directory for all scans (default: `./network_scans`)
- `OUTPUT_FORMAT`: Output format - `json` or `html` (default: `json`)
- `USE_PARALLEL`: Enable parallel processing (default: `true`)
- `DATABASE_FILE`: Centralized database location

**Output Structure:**
```
network_scans/
├── 20260123_143022/           # Timestamp folder
│   ├── 192_168_1_0_24/        # Network folder
│   │   ├── 192_168_1_1.json
│   │   ├── 192_168_1_2.json
│   │   └── ...
│   ├── 192_168_2_0_24/
│   │   └── ...
│   └── 10_0_0_0_26/
│       └── ...
└── scans.db                   # Centralized database
```

---

### 4. Scan with Application Modules (`batch_scan_with_modules.sh`)

Demonstrates batch scanning with enterprise application integration.

**Features:**
- NetBox IPAM integration
- CheckMK monitoring integration
- OpenVAS vulnerability scanning
- Custom credentials file support
- Full reporting mode

**Usage:**
```bash
# First, configure credentials
cp ../config/app_credentials.example.json ../config/app_credentials.json
# Edit app_credentials.json with your actual credentials

# Then run the scan
chmod +x batch_scan_with_modules.sh
./batch_scan_with_modules.sh
```

**Configuration:**
Edit the script to change:
- `NETWORK`: The CIDR network to scan (default: `192.168.1.0/28`)
- `OUTPUT_FOLDER`: Where to save results (default: `./module_scan_results`)
- `ENABLE_NETBOX`: Enable NetBox queries (default: `true`)
- `ENABLE_CHECKMK`: Enable CheckMK queries (default: `true`)
- `ENABLE_OPENVAS`: Enable OpenVAS queries (default: `false`)
- `CREDENTIALS_FILE`: Path to credentials file

**Requirements:**
- Valid credentials in `app_credentials.json`
- Network access to enterprise systems
- Proper authentication configured

---

### 5. HTML Report Generation (`batch_scan_html_report.sh`)

Generates HTML reports with an index page for easy browsing.

**Features:**
- HTML output format
- Automatic index page generation
- Styled reports with tables
- Easy browser viewing
- Full reporting mode

**Usage:**
```bash
chmod +x batch_scan_html_report.sh
./batch_scan_html_report.sh
```

**Configuration:**
Edit the script to change:
- `NETWORK`: The CIDR network to scan (default: `192.168.1.0/28`)
- `OUTPUT_FOLDER`: Where to save reports (default: `./html_reports`)
- `REPORTING_MODE`: Verbosity level - `dense`, `full`, or `full-err` (default: `full`)

**Output:**
- Individual HTML reports for each IP
- `index.html` with links to all reports
- Styled with CSS for professional appearance

**Viewing Reports:**
```bash
# Linux
xdg-open ./html_reports/index.html

# macOS
open ./html_reports/index.html

# Windows
start ./html_reports/index.html
```

---

## General Usage Tips

### Making Scripts Executable

All scripts need execute permissions:
```bash
chmod +x *.sh
```

### Customizing Scripts

Each script has a configuration section at the top. Edit these variables to customize behavior:
- Network ranges
- Output locations
- Output formats
- Processing modes
- Module selections

### Testing Before Production

Always test with small networks first:
```bash
# Test with a /30 (4 IPs)
NETWORK="192.168.1.0/30" ./batch_scan_simple.sh

# Test with a /28 (16 IPs)
NETWORK="192.168.1.0/28" ./batch_scan_parallel.sh
```

### Monitoring Progress

All scripts show real-time progress:
- Overall progress: `Processing IP 45/256 [=====>    ] 17.6%`
- Per-IP progress: `192.168.1.45: Classification [====] Module 2 [===>  ]`

### Error Handling

Scripts include error checking and will report:
- Exit codes
- Success/failure status
- File counts
- Disk usage

### Performance Optimization

**For small networks (< 50 IPs):**
- Use sequential processing
- Lower resource usage
- Simpler debugging

**For large networks (> 100 IPs):**
- Use parallel processing
- Significantly faster
- Higher resource usage

### Disk Space Considerations

Approximate disk usage per IP:
- JSON format: ~10-50 KB per IP
- HTML format: ~20-100 KB per IP
- Database: ~5-20 KB per IP

Example for 256 IPs:
- JSON: ~2.5-12.5 MB
- HTML: ~5-25 MB
- Database: ~1.25-5 MB

### Security Considerations

1. **Credentials**: Never commit `app_credentials.json` to version control
2. **Permissions**: Ensure proper file permissions on output folders
3. **Network Scanning**: Only scan networks you have authorization to scan
4. **Rate Limits**: Be aware of external API rate limits (Module 3)
5. **Database**: Protect database files containing scan history

### Troubleshooting

**Script won't run:**
```bash
# Make executable
chmod +x script_name.sh

# Check for syntax errors
bash -n script_name.sh
```

**Batch size exceeded:**
```bash
# Split large networks into smaller chunks
# Instead of /20 (4096 IPs), use multiple /22 (1024 IPs each)
```

**Out of disk space:**
```bash
# Check available space
df -h

# Clean old scans
rm -rf ./old_scan_results/
```

**Module 4 not working:**
```bash
# Verify credentials file exists
ls -la config/app_credentials.json

# Test connectivity to enterprise systems
ping netbox.example.com
```

## Advanced Examples

### Scheduled Scanning with Cron

Add to crontab for automated scanning:
```bash
# Edit crontab
crontab -e

# Add entry (runs daily at 2 AM)
0 2 * * * /path/to/batch_scan_multiple_networks.sh >> /var/log/ip-sentinel-scan.log 2>&1
```

### Integration with Monitoring Systems

Export results to monitoring systems:
```bash
# After scan completes, parse JSON and send to monitoring
for file in scan_results/*.json; do
    # Extract key metrics and send to monitoring API
    curl -X POST https://monitoring.example.com/api/metrics \
         -H "Content-Type: application/json" \
         -d @"$file"
done
```

### Filtering Results

Process JSON results with `jq`:
```bash
# Find all IPs with open port 22
jq -r 'select(.local_info.nmap_results.open_ports | contains([22])) | .ip_address' scan_results/*.json

# Find all IPs in specific classification
jq -r 'select(.classifications[].name == "Private Network") | .ip_address' scan_results/*.json
```

## Support

For more information:
- Main documentation: `../README.md`
- Configuration guide: `../docs/CONFIGURATION.md`
- Usage examples: `../docs/USAGE_EXAMPLES.md`

## Contributing

Feel free to contribute additional example scripts! Submit a pull request with:
- Well-commented script
- Documentation in this README
- Test results from your environment
