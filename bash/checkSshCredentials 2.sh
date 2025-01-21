#!/bin/bash

# Function to check SSH credentials
check_ssh_credentials() {
    local ssh_path=$1

    # Extract username and host from the SSH path
    local user=$(echo "$ssh_path" | awk -F '[@:]' '{print $1}')
    local host=$(echo "$ssh_path" | awk -F '[@:]' '{print $2}')

    echo "Checking SSH credentials for $user@$host..."
    
    # Check if the user and host are correctly parsed
    if [ -z "$user" ] || [ -z "$host" ]; then
        echo "Error: Unable to parse SSH path. Please enter a valid SSH path in the format username@host."
        exit 1
    fi

    # Attempt to SSH into the host
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$user@$host" 'exit' > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "Error: Unable to connect via SSH to $host as $user. Please verify your SSH credentials."
        exit 1
    else
        echo "SSH credentials are valid."
    fi
}

# Prompt for SSH path
read -p "Enter the SSH path (e.g., username@host): " SSH_PATH

# Check SSH credentials
check_ssh_credentials "$SSH_PATH"
