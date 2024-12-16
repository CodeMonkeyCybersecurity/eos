#!/bin/bash

# Prompt user for endpoints if not provided via command-line options
if [ -z "$1" ]; then
    read -p "Enter the computers you want to run this script on (comma-separated, e.g., endpoint1,endpoint2,endpoint3): " ENDPOINTS_INPUT
    IFS=',' read -r -a ENDPOINTS <<< "$ENDPOINTS_INPUT"
else
    IFS=',' read -r -a ENDPOINTS <<< "$1"
fi

# Prompt for SSH username
read -p "Enter the SSH username: " SSH_USER

# Default command
DEFAULT_COMMAND="hostname"

# Prompt for the command to run (or use the default)
read -p "Enter the command to run on endpoints (or press Enter for default: $DEFAULT_COMMAND): " COMMAND
COMMAND="${COMMAND:-$DEFAULT_COMMAND}"

# Verify endpoints
if [ ${#ENDPOINTS[@]} -eq 0 ]; then
    echo "Error: No endpoints specified."
    exit 1
fi

# Run the command on each endpoint
for ENDPOINT in "${ENDPOINTS[@]}"; do
    echo "Running command on $ENDPOINT..."
    ssh "${SSH_USER}@${ENDPOINT}" "$COMMAND" &
done

# Wait for all background processes to complete
wait

echo "Commands completed on all endpoints."