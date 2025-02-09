#!/usr/bin/env python3
import os
import subprocess
import sys
import shutil

# Directory where we want to deploy the docker-compose file.
DEPLOY_DIR = '/opt/keycloak'
# The expected name of the compose file.
COMPOSE_FILE = 'docker-compose.yml'

def main():
    # Verify that the docker-compose.yml file exists in the current directory.
    if not os.path.exists(COMPOSE_FILE):
        print(f"Error: {COMPOSE_FILE} not found in the current directory.")
        sys.exit(1)
    
    # Create the deployment directory if it does not exist.
    if not os.path.exists(DEPLOY_DIR):
        print(f"Creating directory {DEPLOY_DIR}...")
        try:
            os.makedirs(DEPLOY_DIR, exist_ok=True)
        except PermissionError:
            print("Permission denied while creating the directory. Please run this script with elevated privileges.")
            sys.exit(1)
    
    # Copy the docker-compose.yml file into /opt/keycloak.
    destination = os.path.join(DEPLOY_DIR, COMPOSE_FILE)
    print(f"Copying {COMPOSE_FILE} to {destination}...")
    try:
        shutil.copy2(COMPOSE_FILE, destination)
    except Exception as e:
        print(f"Error copying file: {e}")
        sys.exit(1)
    
    # Change working directory to the deployment directory.
    os.chdir(DEPLOY_DIR)
    
    # Run docker-compose to deploy the services.
    print("Deploying services with 'docker-compose up -d'...")
    try:
        subprocess.run(['docker-compose', 'up', '-d'], check=True)
    except subprocess.CalledProcessError as e:
        print("Error: docker-compose command failed:", e)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: docker-compose command not found. Ensure Docker Compose is installed and available in your PATH.")
        sys.exit(1)
    
    print("Deployment complete!")

if __name__ == '__main__':
    main()
