#!/bin/bash
# /utilities/start.sh
# Resolve the base directory of the current script
PROJECT_ROOT=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../")
echo "PROJECT_ROOT: $PROJECT_ROOT"
echo ""
UTILITIES_DIR="$PROJECT_ROOT/utilities"
echo "UTILITIES_DIR: $UTILITIES_DIR"
echo ""
source "$UTILITIES_DIR/checkSudo.sh" # Source checkSudo.sh
set -xe
echo ""
VARIABLES_CONF="$PROJECT_ROOT/variables.conf"
echo ""
source "$VARIABLES_CONF"
echo ""
source "$UTILITIES_DIR/timestamp.sh"
echo ""
source "$UTILITIES_DIR/userHostnameStamp.sh"
echo ""
source "$UTILITIES_DIR/stamp.sh"
echo ""
source "$UTILITIES_DIR/log.sh"
