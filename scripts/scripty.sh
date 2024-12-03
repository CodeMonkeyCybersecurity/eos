#!/bin/bash

# Create a directory for log files if it doesn't exist
LOG_DIR="mnemosyne_logs"
mkdir -p "$LOG_DIR"

# Initialize variables
LINE_LIMIT=1000
FILE_COUNT=1
CURRENT_FILE="$LOG_DIR/$(date +"%Y-%m-%d_%H-%M")_log_$FILE_COUNT.txt"

# Function to check and rotate log files
rotate_log_file() {
    if [[ $(wc -l < "$CURRENT_FILE") -ge $LINE_LIMIT ]]; then
        ((FILE_COUNT++))
        CURRENT_FILE="$LOG_DIR/$(date +"%Y-%m-%d_%H-%M")_log_$FILE_COUNT.txt"
        echo "Switched to new log file: $CURRENT_FILE"
    fi
}

# Start the script command with logging to the initial file
echo "Starting logging to $CURRENT_FILE"
script -q -c "/bin/zsh" "$CURRENT_FILE" | while read -r line; do
    rotate_log_file
done
