#!/bin/bash

set -xe

../utils/checkSudo.sh

mkdir -p /opt/dmesgs

dmesg > "/opt/dmesgs/$(date +"%Y-%m-%d_%H-%M")_dmesg.txt"

ls -lah /opt/dmesgs

set +x

echo "finis"
