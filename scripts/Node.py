import os
import shutil
import subprocess
import sys

# Define paths
home_dir = os.path.expanduser("~")
node_dir = os.path.join(home_dir, "node-docker")
backup_dir = "/etc/eos/nginx-docker"
docker_compose_file = os.path.join(node_dir, "docker-compose.yaml")
backup_docker_compose_file = os.path.join(backup_dir, "docker-compose.yaml")

# Ensure directories exist
def create_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"Created directory: {path}")

# Create docker-compose.yaml file for Node.js and Nginx
def create_docker_compose():
    compose_content = """version: '3'
services:
  node:
    image: node:latest
    container_name: node-app
    volumes:
      - ./node-app:/usr/src/app
    ports:
      - "3000:3000"
    command: npm start
  nginx:
    image: nginx:latest
    container_name: nginx-proxy
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - node
"""
    with open(docker_compose_file, "w") as f:
        f.write(compose_content)
    print(f"Created docker-compose.yaml in {node_dir}")

# Backup docker-compose.yaml to /etc/eos/nginx-docker
def backup_docker_compose():
    create_directory(backup_dir)
    shutil.copy2(docker_compose_file, backup_docker_compose_file)
    print(f"Backed up docker-compose.yaml to {backup_dir}")

# Update UFW to allow necessary ports for Node.js and Nginx
def update_ufw():
    subprocess.run(["sudo", "ufw", "allow", "3000"], check=True)
    subprocess.run(["sudo", "ufw", "allow", "80"], check=True)
    subprocess.run(["sudo", "ufw", "allow", "443"], check=True)
    subprocess.run(["sudo", "ufw", "reload"], check=True)
    print("Updated UFW rules.")

# SSL Management
def manage_ssl(action, domain=None):
    if action == "get":
        subprocess.run(["sudo", "certbot", "--nginx", "-d", domain], check=True)
        print(f"Obtained SSL certificate for {domain}")
    elif action == "renew":
        subprocess.run(["sudo", "certbot", "renew"], check=True)
        print("Renewed SSL certificates.")
    elif action == "check":
        subprocess.run(["sudo", "certbot", "certificates"], check=True)
        print("Checked SSL certificates.")

# Start Docker containers
def start_containers():
    subprocess.run(["docker-compose", "up", "-d"], check=True)
    print("Started Node.js and Nginx containers.")

# Stop Docker containers
def stop_containers():
    subprocess.run(["docker-compose", "down"], check=True)
    print("Stopped Node.js and Nginx containers.")

# List domains and subdomains
def list_domains():
    print("Listing domains and subdomains...")
    subprocess.run(["sudo", "certbot", "certificates"], check=True)

# Check Docker and Nginx configurations
def check_configs():
    print("Checking Docker and Nginx configurations...")
    subprocess.run(["docker-compose", "config"], check=True)
    subprocess.run(["nginx", "-t"], check=True)

# Plan deployment process
def plan_deployment():
    print("Planning deployment...")
    # Add planning steps or pre-checks for deployment

# Implement deployment process
def implement_deployment():
    print("Implementing deployment...")
    start_containers()

# Main function with argument parsing
def main():
    if len(sys.argv) < 2:
        print("Usage: setupNode.py [--list | --ssl <action> | --start | --stop | --check-configs | --backup-configs | --plan | --implement]")
        sys.exit(1)

    flag = sys.argv[1]
    
    if flag == "--list":
        list_domains()

    elif flag == "--ssl":
        if len(sys.argv) < 3:
            print("Usage: setupNode.py --ssl [get|check|renew] [domain (if 'get')]")
            sys.exit(1)
        action = sys.argv[2]
        domain = sys.argv[3] if len(sys.argv) > 3 else None
        manage_ssl(action, domain)

    elif flag == "--start":
        start_containers()

    elif flag == "--stop":
        stop_containers()

    elif flag == "--check-configs":
        check_configs()

    elif flag == "--backup-configs":
        backup_docker_compose()

    elif flag == "--plan":
        plan_deployment()

    elif flag == "--implement":
        implement_deployment()

    else:
        print(f"Unknown option: {flag}")
        sys.exit(1)

if __name__ == "__main__":
    main()
