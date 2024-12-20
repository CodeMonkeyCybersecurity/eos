#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/checkSudo.sh"
set -xe
# Resolve the directory of the current script
VARIABLES_CONF="$(cd "$SCRIPT_DIR/.." && pwd)/variables.conf"
source "$VARIABLES_CONF"
# Source log.sh using an absolute path
source "$SCRIPT_DIR/timestamp.sh"
source "$SCRIPT_DIR/userHostnameStamp.sh"
source "$SCRIPT_DIR/stamp.sh"
source "$SCRIPT_DIR/log.sh"