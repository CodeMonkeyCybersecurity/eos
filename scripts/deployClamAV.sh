#!/bin/bash
# Simple script to deploy ClamAV on Ubuntu

# Exit immediately if a command exits with a non-zero status
set -e

echo "Updating package lists..."
sudo apt-get update

echo "Installing ClamAV and ClamAV daemon..."
sudo apt-get install -y clamav clamav-daemon

# Stop the freshclam service so that we can update the virus definitions without conflicts
echo "Stopping the freshclam service..."
sudo systemctl stop clamav-freshclam

echo "Updating ClamAV virus definitions..."
sudo freshclam

# Restart the freshclam service to resume automatic updates
echo "Starting the freshclam service..."
sudo systemctl start clamav-freshclam

echo "ClamAV deployment complete!"
