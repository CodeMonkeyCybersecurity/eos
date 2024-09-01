#!/bin/bash

# Function to check installed drives
check_drives() {
    echo "Listing all installed drives:"
    sudo fdisk -l
    echo "Please carefully note down the device names of the drives you want to pool."
}

# Function to get user input for the ZFS pool
get_user_input() {
    read -p "Enter the name for the new ZFS pool: " pool_name

    # Choose pool type: striped (RAID-0) or mirrored (RAID-1)
    echo "Choose the type of pool:"
    echo "1) Striped Pool (RAID-0, not fault tolerant)"
    echo "2) Mirrored Pool (RAID-1, fault tolerant)"
    read -p "Enter your choice (1 or 2): " pool_type_choice

    # Get drives for the pool
    read -p "Enter the device names of the drives to pool (e.g., /dev/sdb /dev/sdc): " drives

    # Ask for a custom mount point
    read -p "Do you want to specify a custom mount point? (y/n): " custom_mount_choice
    if [[ "$custom_mount_choice" == "y" ]]; then
        read -p "Enter the custom mount point (e.g., /usr/share/pool): " mount_point
        mount_option="-m $mount_point"
    else
        mount_option=""
    fi

    # Confirm if user wants to add '-f' to force pool creation if needed
    read -p "Do you want to add '-f' to force pool creation if there are errors? (y/n): " force_choice
    if [[ "$force_choice" == "y" ]]; then
        force_option="-f"
    else
        force_option=""
    fi
}

# Function to create the ZFS pool
create_zfs_pool() {
    # Choose the appropriate command based on the user's choice
    if [[ "$pool_type_choice" == "1" ]]; then
        echo "Creating a striped pool..."
        sudo zpool create $mount_option $pool_name $drives $force_option
    elif [[ "$pool_type_choice" == "2" ]]; then
        echo "Creating a mirrored pool..."
        sudo zpool create $mount_option $pool_name mirror $drives $force_option
    else
        echo "Invalid choice. Exiting."
        exit 1
    fi
}

# Main function to run the script
main() {
    check_drives
    get_user_input
    create_zfs_pool
    echo "ZFS pool '$pool_name' has been created successfully."
}

# Execute the main function
main
