#!/bin/bash
# Parallel batch scanning example
# Scans a network using parallel processing for better performance

# Configuration
NETWORK="192.168.1.0/24"
OUTPUT_FOLDER="./parallel_scan_results"
OUTPUT_FORMAT="json"
REPORTING_MODE="dense"  # Options: dense, full, full-err

# Create output folder if it doesn't exist
mkdir -p "$OUTPUT_FOLDER"

# Run the parallel scan
echo "Starting parallel batch scan of $NETWORK..."
echo "Output folder: $OUTPUT_FOLDER"
echo "Output format: $OUTPUT_FORMAT"
echo "Reporting mode: $REPORTING_MODE"
echo ""
echo "Note: Parallel processing will use multiple CPU cores"
echo ""

# Build command with optional reporting mode
CMD="ip-sentinel --batch --parallel --$OUTPUT_FORMAT --output-folder $OUTPUT_FOLDER"

if [ "$REPORTING_MODE" = "full" ]; then
    CMD="$CMD --full"
elif [ "$REPORTING_MODE" = "full-err" ]; then
    CMD="$CMD --full-err"
fi

CMD="$CMD $NETWORK"

# Execute the command
eval $CMD

# Check exit status
if [ $? -eq 0 ]; then
    echo ""
    echo "Parallel scan completed successfully!"
    echo "Results saved to: $OUTPUT_FOLDER"
    echo "Total files: $(ls -1 "$OUTPUT_FOLDER" | wc -l)"
    
    # Show disk usage
    echo "Disk usage: $(du -sh "$OUTPUT_FOLDER" | cut -f1)"
else
    echo ""
    echo "Scan failed with error code: $?"
fi
