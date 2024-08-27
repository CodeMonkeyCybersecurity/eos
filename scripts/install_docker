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

sudo curl -sSL https://get.docker.com/ | sh

sudo systemctl start docker
sudo systemctl enable docker

sudo curl -L "https://github.com/docker/compose/releases/download/v2.12.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

sudo chmod +x /usr/local/bin/docker-compose

sudo docker-compose --version
