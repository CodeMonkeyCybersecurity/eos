#!/bin/bash

# Create a directory for log files if it doesn't exist
LOG_DIR="$HOME"

# Initialize variables
LINE_LIMIT=1000
FILE_COUNT=1
CURRENT_FILE="$LOG_DIR/$(date +"%Y-%m-%d_%H-%M")_mnemosyne_$FILE_COUNT.txt"

# Function to check and rotate log files
rotate_log_file() {
    if [[ $(wc -l < "$CURRENT_FILE") -ge $LINE_LIMIT ]]; then
        ((FILE_COUNT++))
        CURRENT_FILE="$LOG_DIR/$(date +"%Y-%m-%d_%H-%M")_mnemosyne_$FILE_COUNT.txt"
        echo "Switched to new log file: $CURRENT_FILE"
    fi
}

# Start the script command with logging to the initial file
echo "Starting logging to $CURRENT_FILE"
script -q /dev/null | tee -a "$CURRENT_FILE" | while IFS= read -r line; do
    echo "$line" | tee -a "$CURRENT_FILE" > /dev/null
    rotate_log_file
done
