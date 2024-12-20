#!/bin/bash 
# /utilities/stamp.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/stamp.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/userHostnameStamp.sh.sh"
STAMP="${TIMESTAMP}_${USER_HOSTNAME_STAMP}"
echo "Your stamp is: $STAMP"