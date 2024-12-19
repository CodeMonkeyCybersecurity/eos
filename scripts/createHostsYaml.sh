#!/bin/bash
# createHostsYaml.sh

set -xe

../utils/checkSudo.sh

# Prompt for user input
read -p "Enter the endpoints you want to manage (comma-separated, e.g., host1,host2,host3): " ENDPOINTS
read -p "Enter the username you want to manage these with: " USER

# Define YAML directory and file
YAML_DIR="/opt/cyberMonkey"
YAML_FILE="$YAML_DIR/hosts.yaml"

# Create the directory and file if they don't exist
mkdir -p "$YAML_DIR"

# Write to YAML file
{
    echo "user: $USER"
    echo "hosts:"
    IFS=',' read -ra HOST_ARRAY <<< "$ENDPOINTS"
    for HOST in "${HOST_ARRAY[@]}"; do
        echo "  - $HOST"
    done
} > "$YAML_FILE"

echo "YAML file created at $YAML_FILE with the following content:"
cat "$YAML_FILE"

set +x

echo "finis"


