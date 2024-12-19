#!/bin/bash
# /scripts/createHostsYaml.sh
set -xe
../utils/checkSudo.sh
../utils/cyberMonkeyDir.sh
../variables.conf
# Prompt for user input
read -p "Enter the endpoints you want to manage (comma-separated, e.g., host1,host2,host3): " ENDPOINTS
read -p "Enter the username you want to manage these with: " USER
# Write to .conf file
{
    echo "user=$USER"
    echo -n "hosts=\""
    IFS=',' read -ra HOST_ARRAY <<< "$ENDPOINTS"
    for HOST in "${HOST_ARRAY[@]}"; do
        echo -n "$HOST "
    done
    echo "\""
} > "$CONF_FILE"
echo ".conf file created at $CONF_FILE with the following content:"
cat "$CONF_FILE"
set +x
echo "finis"
