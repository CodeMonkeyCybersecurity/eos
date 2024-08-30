#!/bin/bash

# Function to check SSH connection
check_ssh_connection() {
    local ssh_path=$1
    local user=$(echo "$ssh_path" | awk -F '[@:]' '{print $1}')
    local host=$(echo "$ssh_path" | awk -F '[@:]' '{print $2}')

    echo "Checking SSH connection to $user@$host..."
    
    if [ -z "$user" ] || [ -z "$host" ]; then
        echo "Error: Unable to parse SSH path. Please enter a valid SSH path in the format username@host."
        exit 1
    fi

    ssh -o BatchMode=yes -o ConnectTimeout=5 "$user@$host" 'exit' > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "Error: Unable to connect via SSH to $host as $user. Please verify your SSH credentials."
        exit 1
    else
        echo "SSH connection successful."
    fi
}

# Function to check if the Borg repository exists and initialize if it does not
check_or_initialize_repo() {
    local repo_path=$1
    local ssh_path=$(echo "$repo_path" | awk -F '://' '{print $2}')
    local user=$(echo "$ssh_path" | awk -F '[@:]' '{print $1}')
    local host=$(echo "$ssh_path" | awk -F '[@:]' '{print $2}')
    local repo_dir=$(echo "$ssh_path" | awk -F '[@:]' '{print $3}')

    echo "Checking Borg repository path: $repo_path..."

    # Check if the repository exists by attempting to list it
    ssh "$user@$host" "borg list $repo_dir" > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "Error: Unable to access the repository at $repo_path."
        
        # Prompt to initialize the repository
        read -p "Do you want to initialize a new Borg repository at this path? (y/n): " init_choice
        if [ "$init_choice" == "y" ]; then
            # Ensure the directory exists and is writable
            ssh "$user@$host" "mkdir -p $repo_dir && chmod 700 $repo_dir"
            if [ $? -ne 0 ]; then
                echo "Error: Failed to create or set permissions for the directory $repo_dir on the remote server."
                echo "You will likely need to create this yourself manually, then try this again."
                exit 1
            fi

            # Initialize the Borg repository
            ssh "$user@$host" "borg init --encryption=repokey $repo_dir"
            if [ $? -eq 0 ]; then
                echo "Borg repository initialized successfully at $repo_path."
            else
                echo "Error: Failed to initialize the Borg repository at $repo_path."
                exit 1
            fi
        else
            echo "Exiting without initializing the repository."
            exit 1
        fi
    else
        echo "Repository path is valid and accessible."
    fi
}

# Function to ensure the SSH path is correctly formatted
ensure_ssh_prefix() {
    local path=$1
    if [[ "$path" != ssh://* ]]; then
        path="ssh://$path"
    fi
    echo "$path"
}

# Main function
troubleshoot_borg_repo() {
    read -p "Enter the BORG_REPO path (e.g., /mnt/borg-repo or ssh://username@host:/path/to/repo): " BORG_REPO
    BORG_REPO=$(ensure_ssh_prefix "$BORG_REPO")

    # Check SSH connection
    SSH_PATH=$(echo "$BORG_REPO" | awk -F '://' '{print $2}')
    check_ssh_connection "$SSH_PATH"

    # Check or initialize the Borg repository
    check_or_initialize_repo "$BORG_REPO"
}

# Run the troubleshooting steps
troubleshoot_borg_repo
