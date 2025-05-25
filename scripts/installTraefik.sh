#!/bin/bash

sudo apt-get update
sudo apt-get install python3-pip
sudo apt install python3.12-venv
python3 -m venv ~/myenv
source ~/myenv/bin/activate
pip install --upgrade requests urllib3 docker docker-compose
python install_traefik.py

# Function to check if Docker is installed
check_docker() {
  if ! [ -x "$(command -v docker)" ]; then
    echo "Error: Docker is not installed. Please install Docker and try again."
    exit 1
  fi
}

# Function to pull the latest Traefik image
pull_traefik_image() {
  echo "Pulling the latest Traefik Docker image..."
  docker pull traefik:v2.10
  if [ $? -ne 0 ]; then
    echo "Failed to pull Traefik image. Exiting..."
    exit 1
  fi
}

# Function to create a Traefik network if it doesn't exist
create_network() {
  NETWORK_NAME="traefik_proxy"
  
  if ! docker network ls | grep -q $NETWORK_NAME; then
    echo "Creating Docker network: $NETWORK_NAME"
    docker network create $NETWORK_NAME
    if [ $? -ne 0 ]; then
      echo "Failed to create Docker network. Exiting..."
      exit 1
    fi
  else
    echo "Docker network $NETWORK_NAME already exists."
  fi
}

# Function to start Traefik container
start_traefik() {
  echo "Starting Traefik container..."
  docker run -d \
    --name traefik \
    --restart unless-stopped \
    --network traefik_proxy \
    -p 80:80 \
    -p 443:443 \
    -p 8080:8080 \
    -v /var/run/container.sock:/var/run/container.sock \
    -v $PWD/traefik.toml:/etc/traefik/traefik.toml \
    traefik:v2.10
  if [ $? -ne 0 ]; then
    echo "Failed to start Traefik container. Exiting..."
    exit 1
  fi
  echo "Traefik is up and running."
}

# Function to create a basic Traefik configuration file
create_config() {
  CONFIG_FILE="traefik.toml"
  
  if [ ! -f $CONFIG_FILE ]; then
    echo "Creating Traefik configuration file: $CONFIG_FILE"
    cat <<EOF > $CONFIG_FILE
[entryPoints]
  [entryPoints.web]
    address = ":80"
  [entryPoints.websecure]
    address = ":443"

[api]
  dashboard = true
  insecure = true

[providers]
  docker = true
EOF
  else
    echo "Configuration file $CONFIG_FILE already exists."
  fi
}

# Main script execution
main() {
  check_docker
  pull_traefik_image
  create_network
  create_config
  start_traefik
}

# Run the script
main
