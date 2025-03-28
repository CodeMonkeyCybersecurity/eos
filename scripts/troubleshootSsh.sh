#!/bin/bash

# Function to check SSH connection
check_ssh_connection() {
    local ssh_path=$1

    # Remove any single quotes from the SSH path
    ssh_path=$(echo "$ssh_path" | sed "s/'//g")

    # Extract username and host from the SSH path
    local user=$(echo "$ssh_path" | awk -F '[@:]' '{print $1}')
    local host=$(echo "$ssh_path" | awk -F '[@:]' '{print $2}')

    echo "Checking SSH connection to $user@$host..."
    
    if [ -z "$user" ] || [ -z "$host" ]; then
        echo "Error: Unable to parse SSH path. Please enter a valid SSH path in the format username@host."
        exit 1
    fi

    # Attempt to SSH into the host
    ssh -i "$SSH_KEY_PATH" -o BatchMode=yes -o ConnectTimeout=5 "$user@$host" 'exit' > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "Error: Unable to connect via SSH to $host as $user. Please verify your SSH credentials."
        exit 1
    else
        echo "SSH connection successful."
    fi
}

# Function to check SSH key permissions
check_ssh_key_permissions() {
    local ssh_key=$1
    if [ -f "$ssh_key" ]; then
        echo "Checking SSH key permissions for $ssh_key..."
        key_permissions=$(stat -c "%a" "$ssh_key")
        if [ "$key_permissions" != "600" ]; then
            echo "Warning: SSH key permissions should be 600. Current permissions are $key_permissions."
            chmod 600 "$ssh_key"
            echo "Permissions have been corrected to 600."
        else
            echo "SSH key permissions are correct."
        fi
    else
        echo "Error: SSH key file not found at $ssh_key."
        exit 1
    fi
}

# Function to check if SSH service is running on the remote server
check_ssh_service() {
    local ssh_path=$1

    # Remove any single quotes from the SSH path
    ssh_path=$(echo "$ssh_path" | sed "s/'//g")

    local user=$(echo "$ssh_path" | awk -F '[@:]' '{print $1}')
    local host=$(echo "$ssh_path" | awk -F '[@:]' '{print $2}')

    echo "Checking if SSH service is running on $host..."
    ssh -i "$SSH_KEY_PATH" -o BatchMode=yes -o ConnectTimeout=5 "$user@$host" 'systemctl is-active ssh' > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "Error: SSH service is not running on $host or you don't have permission to check the service status."
        exit 1
    else
        echo "SSH service is running on $host."
    fi
}

# Function to list available SSH keys and prompt the user to select one
select_ssh_key() {
    echo "Available SSH keys in ~/.ssh/:"
    ssh_keys=($(ls ~/.ssh/*.pub | sed 's/.pub$//'))
    
    if [ ${#ssh_keys[@]} -eq 0 ]; then
        echo "No SSH keys found in ~/.ssh/. Please generate or add an SSH key."
        exit 1
    fi

    for i in "${!ssh_keys[@]}"; do
        echo "$((i+1)). ${ssh_keys[$i]}"
    done

    read -p "Select an SSH key by number: " key_choice

    if [[ $key_choice -gt 0 && $key_choice -le ${#ssh_keys[@]} ]]; then
        SSH_KEY_PATH="${ssh_keys[$((key_choice-1))]}"
        echo "Selected SSH key: $SSH_KEY_PATH"
    else
        echo "Invalid choice. Exiting."
        exit 1
    fi
}

# Function to troubleshoot SSH connectivity
troubleshoot_ssh() {
    # Prompt for SSH path
    read -p "Enter the SSH path (e.g., username@host): " SSH_PATH

    # Automatically detect and select SSH key
    select_ssh_key

    # Check SSH key permissions
    check_ssh_key_permissions "$SSH_KEY_PATH"

    # Check SSH connection
    check_ssh_connection "$SSH_PATH"

    # Check SSH service on the remote host
    check_ssh_service "$SSH_PATH"

    echo "SSH troubleshooting completed successfully."
}

# Run the troubleshooting steps
troubleshoot_ssh
