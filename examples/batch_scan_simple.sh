#!/bin/bash
# Simple batch scanning example
# Scans a single network and saves results to a folder

# Configuration
NETWORK="192.168.1.0/24"
OUTPUT_FOLDER="./scan_results"
OUTPUT_FORMAT="json"

# Create output folder if it doesn't exist
mkdir -p "$OUTPUT_FOLDER"

# Run the scan
echo "Starting batch scan of $NETWORK..."
echo "Output folder: $OUTPUT_FOLDER"
echo "Output format: $OUTPUT_FORMAT"
echo ""

ip-sentinel --batch --$OUTPUT_FORMAT --output-folder "$OUTPUT_FOLDER" "$NETWORK"

# Check exit status
if [ $? -eq 0 ]; then
    echo ""
    echo "Scan completed successfully!"
    echo "Results saved to: $OUTPUT_FOLDER"
    echo "Total files: $(ls -1 "$OUTPUT_FOLDER" | wc -l)"
else
    echo ""
    echo "Scan failed with error code: $?"
fi
