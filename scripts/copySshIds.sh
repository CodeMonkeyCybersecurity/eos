#!/bin/bash

# Prompt user for endpoints if not provided via command-line options
if [ -z "$1" ]; then
    read -p "Enter the computers you want to copy your ssh key to (comma-separated, e.g., endpoint1,endpoint2,endpoint3): " ENDPOINTS_INPUT
    IFS=',' read -r -a ENDPOINTS <<< "$ENDPOINTS_INPUT"
else
    IFS=',' read -r -a ENDPOINTS <<< "$1"
fi

# Prompt for SSH username
read -p "Enter the SSH username: " SSH_USER

# Verify endpoints
if [ ${#ENDPOINTS[@]} -eq 0 ]; then
    echo "Error: No endpoints specified."
    exit 1
fi

# Run ssh-copy-id on each endpoint
for ENDPOINT in "${ENDPOINTS[@]}"; do
    echo "Copying your SSH key to $ENDPOINT..."
    ssh-copy-id "${SSH_USER}@${ENDPOINT}"
    if [ $? -eq 0 ]; then
        echo "Successfully copied SSH key to $ENDPOINT."
    else
        echo "Failed to copy SSH key to $ENDPOINT."
    fi
done

echo "SSH key copy process completed on all endpoints."