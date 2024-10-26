#!/bin/bash

# Function to display an error message and exit
error_exit() {
    echo "$1" 1>&2
    exit 1
}

# Update package list
echo "Updating package list..."
if ! sudo apt update; then
    error_exit "Failed to update package list."
fi

# Install BorgBackup
echo "Installing BorgBackup..."
if ! sudo apt install -y borgbackup; then
    error_exit "Failed to install BorgBackup."
fi

echo "BorgBackup installation completed successfully."
