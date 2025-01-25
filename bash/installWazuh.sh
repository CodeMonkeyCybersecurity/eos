#!/bin/bash

# Function to print messages
log() {
    echo -e "[INFO] $1"
}

# Function to handle errors
error_exit() {
    echo -e "[ERROR] $1"
    exit 1
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    error_exit "Docker is not installed. Please install Docker and try again."
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    error_exit "Docker Compose is not installed. Please install Docker Compose and try again."
fi

# Set Wazuh Docker Compose repository URL
git clone https://github.com/wazuh/wazuh-docker.git -b v4.8.2
cd wazuh-docker 
cd single-node

# Download the Wazuh Docker Compose file
log "Downloading Wazuh Docker Compose file..."
curl -sSL $REPO_URL -o $DOCKER_COMPOSE_FILE || error_exit "Failed to download the Docker Compose file."

# Set up Wazuh configuration (optional - adjust environment variables if needed)
log "Setting up Wazuh environment..."
export ELASTIC_VERSION="7.17.0"
export WAZUH_VERSION="4.3.10"
export WAZUH_MANAGER_IP="0.0.0.0"

# Run Docker Compose to start Wazuh
log "Starting Wazuh using Docker Compose..."
docker-compose -f $DOCKER_COMPOSE_FILE up -d || error_exit "Failed to start Wazuh using Docker Compose."

# Verify that Wazuh containers are running
log "Checking Wazuh containers..."
docker-compose ps || error_exit "Wazuh containers are not running as expected."

log "Wazuh installation in Docker completed successfully."
