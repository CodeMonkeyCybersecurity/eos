import os
import subprocess
import sys

def check_docker_installed():
    """Check if Docker is installed on the system."""
    try:
        subprocess.run(['docker', '--version'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Docker is not installed. Please install Docker and try again.")
        sys.exit(1)

def get_user_input(prompt, default=None):
    """Get user input with an optional default value."""
    if default:
        user_input = input(f"{prompt} [{default}]: ") or default
    else:
        user_input = input(f"{prompt}: ")
    return user_input

def install_traefik():
    """Install Traefik using Docker."""
    # Get user input for Traefik configuration
    domain_name = get_user_input("Enter your domain name for Traefik", "example.com")
    email = get_user_input("Enter your email for Let's Encrypt", "admin@example.com")
    network_name = get_user_input("Enter the Docker network name", "traefik-net")
    traefik_version = get_user_input("Enter the Traefik version", "v2.10")

    # Create Docker network if it doesn't exist
    try:
        subprocess.run(['docker', 'network', 'create', network_name], check=True)
        print(f"Docker network '{network_name}' created.")
    except subprocess.CalledProcessError:
        print(f"Docker network '{network_name}' already exists or failed to create.")

    # Create Traefik configuration files
    config_dir = f"./traefik/{domain_name}"
    os.makedirs(config_dir, exist_ok=True)
    print(f"Configuration directory '{config_dir}' created.")

    # traefik.toml
    traefik_config = f"""
[entryPoints]
  [entryPoints.web]
    address = ":80"
  [entryPoints.websecure]
    address = ":443"

[providers.docker]
  endpoint = "unix:///var/run/docker.sock"
  exposedByDefault = false
  network = "{network_name}"

[certificatesResolvers.myresolver.acme]
  email = "{email}"
  storage = "acme.json"
  [certificatesResolvers.myresolver.acme.httpChallenge]
    entryPoint = "web"
    """

    with open(f"{config_dir}/traefik.toml", "w") as f:
        f.write(traefik_config)

    # acme.json (for storing Let's Encrypt certificates)
    acme_file = f"{config_dir}/acme.json"
    open(acme_file, 'a').close()
    os.chmod(acme_file, 0o600)
    print(f"Created and secured 'acme.json' at '{acme_file}'.")

    # Docker Compose file
    docker_compose = f"""
version: '3'

services:
  traefik:
    image: "traefik:{traefik_version}"
    command:
      - "--api.insecure=true"
      - "--providers.docker"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--certificatesresolvers.myresolver.acme.email={email}"
      - "--certificatesresolvers.myresolver.acme.storage=acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "./traefik/{domain_name}/traefik.toml:/traefik.toml"
      - "./traefik/{domain_name}/acme.json:/acme.json"
    networks:
      - "{network_name}"

networks:
  {network_name}:
    external: true
    """

    with open(f"{config_dir}/docker-compose.yml", "w") as f:
        f.write(docker_compose)

    # Start Traefik using Docker Compose
    try:
        subprocess.run(['docker-compose', '-f', f"{config_dir}/docker-compose.yml", 'up', '-d'], check=True)
        print("Traefik is now up and running.")
    except subprocess.CalledProcessError as e:
        print("Failed to start Traefik. Please check the error above.")
        sys.exit(1)

def main():
    """Main function to wrap the installation process."""
    check_docker_installed()
    install_traefik()

if __name__ == "__main__":
    main()
