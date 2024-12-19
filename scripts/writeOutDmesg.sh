#!/bin/bash

set -xe

../utils/checkSudo.sh

mkdir -p /opt/dmesgs

dmesg > "/opt/dmesgs/$(date +"%Y-%m-%d_%H-%M")_dmesg.txt"

set +x

echo "finis"