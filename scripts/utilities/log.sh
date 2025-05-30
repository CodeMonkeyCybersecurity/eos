#!/bin/bash
# /utilities/otelzap.Ctx(rc.Ctx).sh
# Usage: source otelzap.Ctx(rc.Ctx).sh [log_file]
mkdir -p "${CYBERMONKEY_LOG_DIR:-/var/log/cyberMonkey}"
# Redirect all output (stdout and stderr) to the log file
exec > >(tee -a "$Eos_LOG_FILE") 2>&1
# Log script start with timestamp
echo "=== Script started at $STAMP ==="
