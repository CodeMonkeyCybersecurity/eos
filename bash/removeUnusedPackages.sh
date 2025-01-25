#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

# Update and install deborphan if not already installed
echo "Checking for deborphan..."
if ! command -v deborphan &> /dev/null; then
    echo "deborphan is not installed. Installing it now..."
    apt update
    apt install -y deborphan
fi

echo "Updating package information..."
apt update

# List orphaned packages
echo "Identifying orphaned packages..."
orphans=$(deborphan)
if [ -z "$orphans" ]; then
    echo "No orphaned packages found."
else
    echo "The following orphaned packages were found:"
    echo "$orphans"
    
    read -p "Do you want to remove these packages? (y/n): " remove_orphans
    if [[ "$remove_orphans" =~ ^[Yy]$ ]]; then
        echo "$orphans" | xargs apt remove -y
        echo "Orphaned packages removed."
    else
        echo "Skipping removal of orphaned packages."
    fi
fi

# Run apt autoremove
echo "Running apt autoremove to clean up unused dependencies..."
read -p "Do you want to proceed with apt autoremove? (y/n): " autoremove
if [[ "$autoremove" =~ ^[Yy]$ ]]; then
    apt autoremove -y
    echo "Unused dependencies removed."
else
    echo "Skipping apt autoremove."
fi

# Prompt for manual review of unused kernels
echo "Checking for unused kernels..."
unused_kernels=$(dpkg -l | grep -E 'linux-image-[0-9]+' | grep -v $(uname -r))
if [ -z "$unused_kernels" ]; then
    echo "No unused kernels found."
else
    echo "The following unused kernels were found:"
    echo "$unused_kernels"
    read -p "Do you want to remove these kernels? (y/n): " remove_kernels
    if [[ "$remove_kernels" =~ ^[Yy]$ ]]; then
        echo "$unused_kernels" | awk '{print $2}' | xargs apt remove -y
        echo "Unused kernels removed."
    else
        echo "Skipping removal of unused kernels."
    fi
fi

echo "System cleanup completed!"
