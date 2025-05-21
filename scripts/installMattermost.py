import os
import subprocess
import sys

DOCKER_COMPOSE_FILE = """
version: '3'

services:

  db:
    image: postgres:12
    restart: unless-stopped
    volumes:
      - ./volumes/db:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: mmuser
      POSTGRES_PASSWORD: mmuser_password
      POSTGRES_DB: mattermost
    networks:
      - mattermost-network

  app:
    image: mattermost/mattermost-team-edition:latest
    restart: unless-stopped
    ports:
      - "8065:8065"
    volumes:
      - ./volumes/app/mattermost:/mattermost/data
    environment:
      MM_SQLSETTINGS_DRIVERNAME: postgres
      MM_SQLSETTINGS_DATASOURCE: postgres://mmuser:mmuser_password@db:5432/mattermost?sslmode=disable
    networks:
      - mattermost-network
    depends_on:
      - db

networks:
  mattermost-network:
"""

def check_docker():
    """Check if Docker is installed on the debian."""
    try:
        subprocess.run(["docker", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Docker is not installed or not accessible. Please install Docker and try again.")
        sys.exit(1)

def check_docker_compose():
    """Check if Docker Compose is installed on the debian."""
    try:
        subprocess.run(["docker-compose", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Docker Compose is not installed or not accessible. Please install Docker Compose and try again.")
        sys.exit(1)

def create_docker_compose_file():
    """Create the Docker Compose file for Mattermost."""
    with open('docker-compose.yml', 'w') as f:
        f.write(DOCKER_COMPOSE_FILE)
    print("Docker Compose file created successfully.")

def start_mattermost():
    """Start Mattermost using Docker Compose."""
    try:
        subprocess.run(["docker-compose", "up", "-d"], check=True)
        print("Mattermost is now up and running!")
    except subprocess.CalledProcessError as e:
        print(f"Failed to start Mattermost: {e}")
        sys.exit(1)

def main():
    """Main function to orchestrate the Mattermost installation."""
    print("Starting Mattermost installation...")

    # Step 1: Check if Docker is installed
    check_docker()

    # Step 2: Check if Docker Compose is installed
    check_docker_compose()

    # Step 3: Create Docker Compose file
    create_docker_compose_file()

    # Step 4: Start Mattermost
    start_mattermost()

    print("Mattermost installation completed successfully.")

if __name__ == "__main__":
    main()
