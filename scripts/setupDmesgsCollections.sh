#!/bin/bash
# setupDmesgsCollections.sh 

set -xe

../checkSudo.sh

# Set local path for retrieved files
local_path="/opt/dmesgs/collections"
mkdir -p "$local_path"

# Prompt for user input
read -p "Enter the address of the remote computer (hostname or IP): " remote_host
read -p "Enter the username of the remote computer: " remote_user
remote_path="/opt/dmesgs"

# Function to retrieve a file using SCP
scp_retrieve_file() {
    # Execute the SCP command to recursively copy the directory
    scp -r "$remote_user@$remote_host:$remote_path" "$local_path"

    # Check if the command succeeded
    if [ $? -eq 0 ]; then
        echo "File successfully retrieved from $remote_host."
    else
        echo "Failed to retrieve the file from $remote_host."
        exit 1
    fi
}

# Call the function
scp_retrieve_file

set +x

echo "finis"