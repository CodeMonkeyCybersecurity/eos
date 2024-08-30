#!/bin/bash

# Function to prompt the user for input with a default value
ask() {
    local prompt="$1"
    local default="$2"
    local result

    read -p "$prompt [$default]: " result
    echo "${result:-$default}"
}

# Start creating the docker-compose.yaml
echo "version: '3.8'" > docker-compose.yaml
echo "services:" >> docker-compose.yaml

while true; do
    # Get service name
    service_name=$(ask "Enter the service name" "my_service")

    # Get image name
    image_name=$(ask "Enter the Docker image name" "nginx")

    # Get container name
    container_name=$(ask "Enter the container name" "$service_name")

    # Get port mapping
    port_mapping=$(ask "Enter port mapping (e.g., 8080:80)" "")

    # Get volume mapping
    volume_mapping=$(ask "Enter volume mapping (e.g., ./data:/data)" "")

    # Get environment variables
    env_vars=()
    while true; do
        env_var=$(ask "Enter an environment variable (key=value), or leave blank to stop" "")
        if [ -z "$env_var" ]; then
            break
        fi
        env_vars+=("$env_var")
    done

    # Write service configuration to docker-compose.yaml
    echo "  $service_name:" >> docker-compose.yaml
    echo "    image: $image_name" >> docker-compose.yaml
    echo "    container_name: $container_name" >> docker-compose.yaml
    
    if [ -n "$port_mapping" ]; then
        echo "    ports:" >> docker-compose.yaml
        echo "      - \"$port_mapping\"" >> docker-compose.yaml
    fi

    if [ -n "$volume_mapping" ]; then
        echo "    volumes:" >> docker-compose.yaml
        echo "      - \"$volume_mapping\"" >> docker-compose.yaml
    fi

    if [ ${#env_vars[@]} -gt 0 ]; then
        echo "    environment:" >> docker-compose.yaml
        for env_var in "${env_vars[@]}"; do
            echo "      - \"$env_var\"" >> docker-compose.yaml
        done
    fi

    # Ask if the user wants to add another service
    add_another=$(ask "Do you want to add another service? (y/n)" "n")
    if [ "$add_another" != "y" ]; then
        break
    fi
done

echo "docker-compose.yaml has been created."
