#!/bin/bash

# Script to check Borg repository path

# Function to check Borg repository path
check_repo_path() {
    local repo_path=$1

    echo "Checking Borg repository path: $repo_path..."
    borg list "$repo_path" > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        echo "Error: Unable to access the repository at $repo_path. Please verify the repository path."
        exit 1
    else
        echo "Repository path is valid and accessible."
    fi
}

# Prompt for repository path
read -p "Enter the BORG_REPO path (e.g., /mnt/borg-repo or ssh://username@host:/path/to/repo): " BORG_REPO

# Check the repository path
check_repo_path "$BORG_REPO"
