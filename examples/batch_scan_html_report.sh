#!/bin/bash
# HTML batch scanning example
# Generates HTML reports for each IP address in a network

# Configuration
NETWORK="192.168.1.0/28"
OUTPUT_FOLDER="./html_reports"
REPORTING_MODE="full"  # Options: dense, full, full-err

# Create output folder
mkdir -p "$OUTPUT_FOLDER"

echo "=========================================="
echo "HTML Batch Report Generation"
echo "=========================================="
echo "Network: $NETWORK"
echo "Output folder: $OUTPUT_FOLDER"
echo "Reporting mode: $REPORTING_MODE"
echo ""

# Build command
CMD="ip-sentinel --batch --html --output-folder $OUTPUT_FOLDER"

# Add reporting mode
if [ "$REPORTING_MODE" = "full" ]; then
    CMD="$CMD --full"
elif [ "$REPORTING_MODE" = "full-err" ]; then
    CMD="$CMD --full-err"
fi

CMD="$CMD $NETWORK"

# Execute the scan
echo "Generating HTML reports..."
echo ""

eval $CMD
EXIT_CODE=$?

# Check result
echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "=========================================="
    echo "HTML reports generated successfully!"
    echo "=========================================="
    echo "Reports saved to: $OUTPUT_FOLDER"
    echo "Total files: $(ls -1 "$OUTPUT_FOLDER"/*.html 2>/dev/null | wc -l)"
    echo ""
    
    # Create an index.html file listing all reports
    INDEX_FILE="$OUTPUT_FOLDER/index.html"
    echo "Creating index file: $INDEX_FILE"
    
    cat > "$INDEX_FILE" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>IP-Sentinel Batch Scan Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #333;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        a {
            color: #4CAF50;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .info {
            margin-top: 20px;
            padding: 10px;
            background-color: #e7f3fe;
            border-left: 4px solid #2196F3;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>IP-Sentinel Batch Scan Results</h1>
        <p><strong>Scan Date:</strong> SCAN_DATE</p>
        <p><strong>Network:</strong> NETWORK_CIDR</p>
        <p><strong>Total Reports:</strong> TOTAL_REPORTS</p>
        
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Report</th>
                </tr>
            </thead>
            <tbody>
REPORT_LINKS
            </tbody>
        </table>
        
        <div class="info">
            <strong>Note:</strong> Click on any IP address to view its detailed analysis report.
        </div>
    </div>
</body>
</html>
EOF
    
    # Generate report links
    REPORT_LINKS=""
    for html_file in "$OUTPUT_FOLDER"/*.html; do
        if [ "$html_file" != "$INDEX_FILE" ]; then
            filename=$(basename "$html_file")
            # Extract IP from filename (remove .html and replace _ with .)
            ip_address=$(echo "$filename" | sed 's/.html$//' | tr '_' '.')
            REPORT_LINKS="$REPORT_LINKS                <tr>\n"
            REPORT_LINKS="$REPORT_LINKS                    <td>$ip_address</td>\n"
            REPORT_LINKS="$REPORT_LINKS                    <td><a href=\"$filename\">View Report</a></td>\n"
            REPORT_LINKS="$REPORT_LINKS                </tr>\n"
        fi
    done
    
    # Replace placeholders in index.html
    sed -i "s|SCAN_DATE|$(date)|g" "$INDEX_FILE"
    sed -i "s|NETWORK_CIDR|$NETWORK|g" "$INDEX_FILE"
    sed -i "s|TOTAL_REPORTS|$(ls -1 "$OUTPUT_FOLDER"/*.html 2>/dev/null | grep -v index.html | wc -l)|g" "$INDEX_FILE"
    sed -i "s|REPORT_LINKS|$REPORT_LINKS|g" "$INDEX_FILE"
    
    echo ""
    echo "Index file created: $INDEX_FILE"
    echo ""
    echo "To view reports:"
    echo "  Open in browser: file://$(realpath "$INDEX_FILE")"
    echo "  Or use: xdg-open $INDEX_FILE  (Linux)"
    echo "  Or use: open $INDEX_FILE      (macOS)"
else
    echo "=========================================="
    echo "Report generation failed with error code: $EXIT_CODE"
    echo "=========================================="
fi
