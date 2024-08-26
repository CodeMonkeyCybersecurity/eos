#!/bin/bash

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

# Update the package index
echo "Updating package index..."
sudo apt-get update
check_success "Package index update"

# Install required packages
echo "Installing ca-certificates and curl..."
sudo apt-get install -y ca-certificates curl
check_success "Installation of ca-certificates and curl"

# Create the keyrings directory
echo "Creating /etc/apt/keyrings directory..."
sudo install -m 0755 -d /etc/apt/keyrings
check_success "Directory creation"

# Download Docker's official GPG key
echo "Downloading Docker's GPG key..."
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
check_success "GPG key download"

# Set the appropriate permissions for the GPG key
echo "Setting permissions for the GPG key..."
sudo chmod a+r /etc/apt/keyrings/docker.asc
check_success "Setting GPG key permissions"

# Add Docker repository to Apt sources
echo "Adding Docker repository to Apt sources..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
check_success "Adding Docker repository"

# Update package index again
echo "Updating package index..."
sudo apt-get update
check_success "Package index update"

# Install Docker packages
echo "Installing Docker packages..."
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
check_success "Docker installation"

# Run the hello-world Docker container to verify installation
echo "Running hello-world Docker container..."
sudo docker run hello-world
check_success "Docker test run"

echo "Docker installation and test run completed successfully."
