#!/bin/bash

# Function to check filesystem type of a given partition
check_partition_format() {
    local partition=$1

    # Check if partition exists
    if lsblk | grep -q "$partition"; then
        # Get the filesystem type using lsblk
        fs_type=$(lsblk -no FSTYPE "/dev/$partition")
        
        # Check if filesystem type is empty
        if [[ -z "$fs_type" ]]; then
            echo "No filesystem detected on partition /dev/$partition."
        else
            echo "The filesystem type of /dev/$partition is: $fs_type"
        fi
    else
        echo "Partition /dev/$partition does not exist."
    fi
}

# Prompt user for partition input
read -p "Enter the partition (e.g., sda1, nvme0n1p2): " partition

# Call the function with user input
check_partition_format "$partition"
