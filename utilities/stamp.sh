#!/bin/bash 
# /utilities/stamp.sh

source timestamp.sh
source userHostnameStamp.sh

STAMP="${TIMESTAMP}_${USER_HOSTNAME_STAMP}"
echo "Your stamp is: $STAMP"