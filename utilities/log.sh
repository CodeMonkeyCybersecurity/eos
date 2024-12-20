#!/bin/bash
# /utilities/log.sh
# Usage: source log.sh [log_file]
source stamp.sh
source ../variables.conf
# Default log file if none provided
# Redirect all output (stdout and stderr) to the log file
exec > >(tee -a "$LOG_FILE") 2>&1
# Log script start with timestamp
echo "=== Script started at $STAMP ==="