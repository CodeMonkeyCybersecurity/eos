#!/bin/bash
set -xe

# Resolve the directory of the current script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source log.sh using an absolute path
source "$SCRIPT_DIR/log.sh"