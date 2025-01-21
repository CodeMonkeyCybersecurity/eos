#!/bin/bash

# Function to check if the current directory is a Git repository
function check_git_repo() {
    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        echo "Error: This is not a Git repository. Please navigate to a Git repository and try again."
        exit 1
    fi
}

# Function to update the remote URL
function update_remote_url() {
    # Prompt the user for the new remote URL
    echo "Current remote URLs:"
    git remote -v
    echo ""
    read -p "Enter the new remote URL: " new_url

    # Check if the user entered a URL
    if [[ -z "$new_url" ]]; then
        echo "Error: No URL provided. Exiting."
        exit 1
    fi

    # Update the remote URL
    git remote set-url origin "$new_url"

    # Verify the update
    echo ""
    echo "Updated remote URLs:"
    git remote -v
    echo "The remote URL has been successfully updated to $new_url"
}

# Main script execution
check_git_repo
update_remote_url
