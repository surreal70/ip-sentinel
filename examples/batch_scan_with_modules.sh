#!/bin/bash
# Batch scanning with application modules example
# Demonstrates scanning with NetBox, CheckMK, and other enterprise integrations

# Configuration
NETWORK="192.168.1.0/28"  # Small network for testing
OUTPUT_FOLDER="./module_scan_results"
OUTPUT_FORMAT="json"
REPORTING_MODE="full"

# Module flags (set to true to enable)
ENABLE_NETBOX=true
ENABLE_CHECKMK=true
ENABLE_OPENVAS=false  # Set to true if OpenVAS is configured

# Credentials file (optional, uses default if not specified)
CREDENTIALS_FILE="./config/app_credentials.json"

# Create output folder
mkdir -p "$OUTPUT_FOLDER"

echo "=========================================="
echo "Batch Scan with Application Modules"
echo "=========================================="
echo "Network: $NETWORK"
echo "Output folder: $OUTPUT_FOLDER"
echo "Output format: $OUTPUT_FORMAT"
echo "Reporting mode: $REPORTING_MODE"
echo ""
echo "Enabled modules:"
[ "$ENABLE_NETBOX" = true ] && echo "  - NetBox (IPAM)"
[ "$ENABLE_CHECKMK" = true ] && echo "  - CheckMK (Monitoring)"
[ "$ENABLE_OPENVAS" = true ] && echo "  - OpenVAS (Vulnerability Scanning)"
echo ""

# Build command
CMD="ip-sentinel --batch --$OUTPUT_FORMAT --output-folder $OUTPUT_FOLDER"

# Add reporting mode
if [ "$REPORTING_MODE" = "full" ]; then
    CMD="$CMD --full"
elif [ "$REPORTING_MODE" = "full-err" ]; then
    CMD="$CMD --full-err"
fi

# Add credentials file if specified
if [ -f "$CREDENTIALS_FILE" ]; then
    CMD="$CMD --credentials $CREDENTIALS_FILE"
    echo "Using credentials file: $CREDENTIALS_FILE"
else
    echo "Warning: Credentials file not found: $CREDENTIALS_FILE"
    echo "Application modules may not work without proper credentials"
fi

# Add module flags
[ "$ENABLE_NETBOX" = true ] && CMD="$CMD --netbox"
[ "$ENABLE_CHECKMK" = true ] && CMD="$CMD --checkmk"
[ "$ENABLE_OPENVAS" = true ] && CMD="$CMD --openvas"

# Add network
CMD="$CMD $NETWORK"

echo ""
echo "Command: $CMD"
echo ""
echo "Starting scan..."
echo ""

# Execute the scan
eval $CMD
EXIT_CODE=$?

# Check result
echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "=========================================="
    echo "Scan completed successfully!"
    echo "=========================================="
    echo "Results saved to: $OUTPUT_FOLDER"
    echo "Total files: $(ls -1 "$OUTPUT_FOLDER" | wc -l)"
    echo "Disk usage: $(du -sh "$OUTPUT_FOLDER" | cut -f1)"
    echo ""
    echo "You can view individual results with:"
    echo "  cat $OUTPUT_FOLDER/<ip_address>.json | jq ."
else
    echo "=========================================="
    echo "Scan failed with error code: $EXIT_CODE"
    echo "=========================================="
    echo ""
    echo "Common issues:"
    echo "  - Check credentials file exists and is valid"
    echo "  - Verify application module endpoints are accessible"
    echo "  - Ensure network connectivity to enterprise systems"
fi
