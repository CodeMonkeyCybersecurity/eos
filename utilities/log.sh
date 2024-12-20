#!/bin/bash
# /utilities/log.sh
# Usage: source log.sh [log_file]
# Resolve the directory of the current script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Source log.sh using an absolute path
source "$SCRIPT_DIR/stamp.sh"
source ../variables.conf
# Default log file if none provided
# Redirect all output (stdout and stderr) to the log file
exec > >(tee -a "$LOG_FILE") 2>&1
# Log script start with timestamp
echo "=== Script started at $STAMP ==="