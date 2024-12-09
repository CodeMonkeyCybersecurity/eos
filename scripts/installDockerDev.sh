#!/bin/bash

# Exit on any error
set -e

# Function to check if the last command was successful
check_success() {
  if [ $? -ne 0 ]; then
    echo "Error: $1 failed. Exiting."
    exit 1
  fi
}

# Ask the user for confirmation
read -p "This script will install Docker. Do you want to continue? (y/n): " confirm
if [[ $confirm != "y" ]]; then
  echo "Installation aborted by user."
  exit 0
fi

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
check_success "Downloading Docker installation script"

sudo sh get-docker.sh
check_success "Docker installation"

# Add user to the Docker group
sudo groupadd docker || true  # Ignore if the group already exists
sudo usermod -aG docker $USER
newgrp docker
echo "Please log out and back in for group changes to take effect."

# Enable Docker service
sudo systemctl enable docker.service
sudo systemctl start docker.service
check_success "Starting and enabling Docker to start on boot"

sudo systemctl enable containerd.service
sudo systemctl start containerd.service
check_success "Starting and enabling containerd.service to start on boot"

# Run a test Docker container
docker run hello-world
check_success "Running Docker hello-world test"

# Clean up
rm -f get-docker.sh
