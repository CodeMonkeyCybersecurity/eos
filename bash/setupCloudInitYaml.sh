#!/bin/bash

# Get system details
HOSTNAME=$(hostname)
USER=$(whoami)
SSH_KEY=$(cat ~/.ssh/id_ed25519.pub)

# Get list of installed packages
INSTALLED_PACKAGES=$(dpkg --get-selections | awk '/install/ {print $1}' | xargs)

# Create the cloud-init configuration file
cat <<EOF > /etc/cloud/cloud.cfg.d/99-custom-config.yaml
#cloud-config
hostname: $HOSTNAME
manage_etc_hosts: true

# Networking
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true

# Users
users:
  - name: $USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $SSH_KEY

# Packages to install
package_update: true
package_upgrade: true
packages:
  $(echo $INSTALLED_PACKAGES)

# Run commands on first boot
runcmd:
  - echo "Cloud-init finished successfully!" >> /var/log/cloud-init-output.log
EOF

echo "Cloud-init file generated at /etc/cloud/cloud.cfg.d/99-custom-config.yaml"
