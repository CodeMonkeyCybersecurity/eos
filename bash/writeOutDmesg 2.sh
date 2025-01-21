#!/bin/bash
set -xe
../utils/checkSudo.sh
source ../variables.conf
mkdir -p "$DMESGS_DIR"
dmesg > "$DMESGS_DIR/$(date +"%Y-%m-%d_%H-%M")_$(hostname)_dmesg.txt"
ls -lah "$DMESGS_DIR"
set +x
echo "finis"
