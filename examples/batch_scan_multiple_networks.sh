#!/bin/bash
# Multiple network batch scanning example
# Scans multiple networks and organizes results by network and timestamp

# Configuration
NETWORKS=(
    "192.168.1.0/24"
    "192.168.2.0/24"
    "10.0.0.0/26"
    "172.16.0.0/28"
)

OUTPUT_BASE="./network_scans"
OUTPUT_FORMAT="json"
USE_PARALLEL=true
DATABASE_FILE="${OUTPUT_BASE}/scans.db"

# Create timestamp for this scan run
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_RUN_FOLDER="${OUTPUT_BASE}/${TIMESTAMP}"

# Create base output folder
mkdir -p "$OUTPUT_BASE"

echo "=========================================="
echo "Multi-Network Batch Scanning"
echo "=========================================="
echo "Scan timestamp: $TIMESTAMP"
echo "Output base: $OUTPUT_BASE"
echo "Database: $DATABASE_FILE"
echo "Parallel processing: $USE_PARALLEL"
echo "Networks to scan: ${#NETWORKS[@]}"
echo ""

# Counter for tracking progress
NETWORK_COUNT=0
TOTAL_NETWORKS=${#NETWORKS[@]}
TOTAL_IPS=0
SUCCESSFUL_SCANS=0
FAILED_SCANS=0

# Scan each network
for network in "${NETWORKS[@]}"; do
    NETWORK_COUNT=$((NETWORK_COUNT + 1))
    
    echo "=========================================="
    echo "Network $NETWORK_COUNT/$TOTAL_NETWORKS: $network"
    echo "=========================================="
    
    # Sanitize network name for folder (replace / and . with _)
    folder_name=$(echo "$network" | tr '/' '_' | tr '.' '_' | tr ':' '_')
    output_folder="${SCAN_RUN_FOLDER}/${folder_name}"
    
    # Create network-specific output folder
    mkdir -p "$output_folder"
    
    # Build command
    CMD="ip-sentinel --batch --$OUTPUT_FORMAT --output-folder $output_folder --database $DATABASE_FILE"
    
    if [ "$USE_PARALLEL" = true ]; then
        CMD="$CMD --parallel"
    fi
    
    CMD="$CMD $network"
    
    # Execute the scan
    echo "Command: $CMD"
    echo ""
    
    eval $CMD
    EXIT_CODE=$?
    
    # Check result
    if [ $EXIT_CODE -eq 0 ]; then
        SUCCESSFUL_SCANS=$((SUCCESSFUL_SCANS + 1))
        FILE_COUNT=$(ls -1 "$output_folder" | wc -l)
        TOTAL_IPS=$((TOTAL_IPS + FILE_COUNT))
        echo ""
        echo "✓ Network $network completed successfully"
        echo "  Files created: $FILE_COUNT"
        echo "  Location: $output_folder"
    else
        FAILED_SCANS=$((FAILED_SCANS + 1))
        echo ""
        echo "✗ Network $network failed with error code: $EXIT_CODE"
    fi
    
    echo ""
done

# Final summary
echo "=========================================="
echo "Scan Summary"
echo "=========================================="
echo "Total networks scanned: $TOTAL_NETWORKS"
echo "Successful: $SUCCESSFUL_SCANS"
echo "Failed: $FAILED_SCANS"
echo "Total IPs analyzed: $TOTAL_IPS"
echo ""
echo "Results location: $SCAN_RUN_FOLDER"
echo "Database: $DATABASE_FILE"

# Show disk usage
if [ -d "$SCAN_RUN_FOLDER" ]; then
    echo "Total disk usage: $(du -sh "$SCAN_RUN_FOLDER" | cut -f1)"
fi

echo ""
echo "Scan run completed at: $(date)"
echo "=========================================="
