#!/bin/bash

# Get the original directory (where the script is run from)
ORIGINAL_DIR=$(pwd)
check_sudo() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m✘ This script must be run as root. Please use sudo.\e[0m"
    exit 1
  else
    echo -e "✔ Running as root."
  fi
}

# Ensure the script is run as root
check_sudo

# Create the target directory
mkdir -p /usr/local/bin/eos/scripts

# Move contents of the original directory to /usr/local/bin/eos
mv "$ORIGINAL_DIR"/* /usr/local/bin/eos/

# Make the files executable
chmod +x /usr/local/bin/eos
chmod +x /usr/local/bin/eos/scripts/*.sh || echo "No scripts found in /usr/local/bin/eos/scripts/"

echo -e "\e[32m✔ Installation complete.\e[0m"
