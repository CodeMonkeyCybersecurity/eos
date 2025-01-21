#!/bin/bash

# Function to format a partition
format_partition() {
    local partition=$1
    local fs_type=$2

    # Check if partition exists
    if lsblk | grep -q "$partition"; then
        
        # Unmount the partition if it is mounted
        if mount | grep -q "/dev/$partition"; then
            echo "Unmounting /dev/$partition..."
            sudo umount "/dev/$partition"
            if [ $? -ne 0 ]; then
                echo "Error: Failed to unmount /dev/$partition. Exiting."
                exit 1
            fi
        fi

        # Format the partition
        echo "Formatting /dev/$partition to $fs_type..."
        case $fs_type in
            ext4)
                sudo mkfs.ext4 "/dev/$partition"
                ;;
            ext3)
                sudo mkfs.ext3 "/dev/$partition"
                ;;
            ext2)
                sudo mkfs.ext2 "/dev/$partition"
                ;;
            xfs)
                sudo mkfs.xfs "/dev/$partition"
                ;;
            btrfs)
                sudo mkfs.btrfs "/dev/$partition"
                ;;
            vfat)
                sudo mkfs.vfat "/dev/$partition"
                ;;
            ntfs)
                sudo mkfs.ntfs "/dev/$partition"
                ;;
            zfs)
                if ! command -zpool &> /dev/null; then
                    echo "Installing ZFS utilities..."
                    sudo apt update && sudo apt install -y  zfsutils-linux
                fi
                sudo zpool create -f "$partition" "/dev/$partition"
                ;;
            *)
                echo "Error: Unsupported filesystem type: $fs_type"
                exit 1
                ;;
        esac

        if [ $? -eq 0 ]; then
            echo "Successfully formatted /dev/$partition to $fs_type."
        else
            echo "Error: Failed to format /dev/$partition to $fs_type."
        fi
    else
        echo "Partition /dev/$partition does not exist."
    fi
}

# Prompt user for partition input
read -p "Enter the partition to format (e.g., sda1, nvme0n1p2): " partition
read -p "Enter the filesystem type (e.g., ext4, xfs, btrfs, vfat, ntfs): " fs_type

# Confirm the action
echo "Warning: Formatting will erase all data on /dev/$partition."
read -p "Are you sure you want to format /dev/$partition to $fs_type? (yes/no): " confirm

if [[ "$confirm" == "yes" ]]; then
    # Call the function to format the partition
    format_partition "$partition" "$fs_type"
else
    echo "Operation cancelled."
fi
