#!/bin/bash
# /utilities/log.sh
# Usage: source log.sh [log_file]
mkdir -p "${CYBERMONKEY_LOG_DIR:-/var/log/cyberMonkey}"
# Redirect all output (stdout and stderr) to the log file
exec > >(tee -a "$EOS_LOG_FILE") 2>&1
# Log script start with timestamp
echo "=== Script started at $STAMP ==="
