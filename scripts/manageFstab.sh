#!/bin/bash

# List available block devices
lsblk -f
echo "Above are the available block devices."

# List block devices with UUIDs
blkid
echo "Above are the block devices with UUIDs."

FABRIC_FSTAB="/etc/fabric/fstab"
sudo mkdir -p "$FABRIC_FSTAB"
sudo cp /etc/fstab "$FABRIC_FSTAB/fstab_backup_$(date +%F)"
ls -l "$FABRIC_FSTAB/"
echo "/etc/fstab backed up to $FABRIC_FSTAB/fstab_backup_$(date +%F)"

# Prompt for the UUID
read -p "Copy the UUID for the drive you want to mount and paste it here now: " UUID
if [[ -z "$UUID" ]]; then
  echo "Error: UUID cannot be empty."
  exit 1
fi
echo "The UUID for the drive you want to mount is: $UUID"

# Prompt for the filesystem type (TYPE)
read -p "Copy the TYPE (e.g., ext4, ntfs, zfs) for the drive you want to mount and paste it here now: " TYPE
if [[ -z "$TYPE" ]]; then
  echo "Error: TYPE cannot be empty."
  exit 1
fi
echo "The TYPE for the drive you want to mount is: $TYPE"

# Prompt for the mount point
read -p "Enter the directory where you want to mount the new drive (e.g., /mnt/usbdrive): " MOUNT_POINT
if [[ -z "$MOUNT_POINT" ]]; then
  echo "Error: Mount point cannot be empty."
  exit 1
fi

# Ensure the mount point starts with '/'
if [[ "$MOUNT_POINT" != /* ]]; then
  echo "Error: Invalid mount point. It should start with '/'."
  exit 1
fi

# Create the mount point directory if it does not exist
if [[ ! -d "$MOUNT_POINT" ]]; then
  sudo mkdir -p "$MOUNT_POINT"
  echo "New directory created at $MOUNT_POINT"
else
  echo "Directory $MOUNT_POINT already exists."
fi

# Add the entry to /etc/fstab
echo "Adding entry to /etc/fstab..."
echo "UUID=$UUID $MOUNT_POINT $TYPE defaults 0 2" | sudo tee -a /etc/fstab > /dev/null

# Display the updated /etc/fstab
echo "Updated /etc/fstab:"
cat /etc/fstab

# Mount all filesystems mentioned in /etc/fstab
echo "Mounting all filesystems from /etc/fstab..."
sudo mount -a

# Display the currently mounted filesystems
echo "Currently mounted filesystems:"
df -h

sudo systemctl daemon-reload
echo "done"
