#!/bin/bash

# Update package list
echo "Updating package list..."
sudo apt update -y || { echo "Failed to update package list. Exiting."; exit 1; }

# Install npm if not already installed
if ! command -v npm &> /dev/null; then
    echo "Installing npm..."
    sudo apt install -y npm || { echo "Failed to install npm. Exiting."; exit 1; }
else
    echo "npm is already installed."
fi

# Install zx globally using npm
if ! command -v zx &> /dev/null; then
    echo "Installing zx globally..."
    sudo npm install -g zx || { echo "Failed to install zx. Exiting."; exit 1; }
else
    echo "zx is already installed."
fi

echo "Installation complete!"
