#!/usr/bin/env python3

import os
import subprocess
import shutil
import sys
import yaml

NGINX_DIR = os.path.expanduser('~/nginx-docker')
DOCKER_COMPOSE_FILE = os.path.join(NGINX_DIR, 'docker-compose.yaml')
BACKUP_DIR = '/etc/eos/nginx-docker'

def run_command(command):
    """Runs a shell command and returns the output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(e.output)
        sys.exit(1)

def list_domains():
    """Lists domains and subdomains."""
    if os.path.exists(DOCKER_COMPOSE_FILE):
        with open(DOCKER_COMPOSE_FILE, 'r') as f:
            config = yaml.safe_load(f)
            if 'services' in config and 'nginx' in config['services']:
                print("Domains and subdomains in Nginx config:")
                for domain in config['services']['nginx'].get('domains', []):
                    print(f"- {domain}")
            else:
                print("No domains found in Nginx service.")
    else:
        print(f"{DOCKER_COMPOSE_FILE} not found!")

def manage_ssl(action):
    """Manages SSL certificates."""
    if action == 'get':
        print("Fetching SSL certificates...")
        run_command("certbot certonly --nginx")
    elif action == 'check':
        print("Checking SSL certificates...")
        run_command("certbot certificates")
    elif action == 'renew':
        print("Renewing SSL certificates...")
        run_command("certbot renew")
    else:
        print("Unknown SSL action. Use 'get', 'check', or 'renew'.")

def start_nginx():
    """Starts Nginx."""
    print("Starting Nginx...")
    run_command(f"docker-compose -f {DOCKER_COMPOSE_FILE} up -d")

def stop_nginx():
    """Stops Nginx."""
    print("Stopping Nginx...")
    run_command(f"docker-compose -f {DOCKER_COMPOSE_FILE} down")

def check_configs():
    """Checks Nginx configurations."""
    print("Checking Nginx configurations...")
    run_command(f"docker-compose -f {DOCKER_COMPOSE_FILE} config")

def backup_configs():
    """Backs up Nginx configurations."""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    print(f"Backing up Nginx configs to {BACKUP_DIR}...")
    shutil.copy(DOCKER_COMPOSE_FILE, BACKUP_DIR)
    print("Backup completed.")

def plan_deployment():
    """Plans the deployment of Nginx on Docker."""
    print("Planning Nginx deployment...")
    # You can expand this with more detailed planning logic if needed.
    print(f"Deploying to: {NGINX_DIR}")
    print(f"Docker Compose File: {DOCKER_COMPOSE_FILE}")

def implement_deployment():
    """Implements the planned Nginx deployment."""
    print("Implementing Nginx deployment...")
    if not os.path.exists(NGINX_DIR):
        os.makedirs(NGINX_DIR)
    
    # Sample Docker Compose content for Nginx
    docker_compose_content = """
    version: '3'
    services:
      nginx:
        image: nginx
        ports:
          - "80:80"
          - "443:443"
        volumes:
          - ./nginx.conf:/etc/nginx/nginx.conf
    """
    
    with open(DOCKER_COMPOSE_FILE, 'w') as f:
        f.write(docker_compose_content)
    
    print(f"Docker Compose file created at {DOCKER_COMPOSE_FILE}.")
    print("Starting Nginx deployment...")
    run_command(f"docker-compose -f {DOCKER_COMPOSE_FILE} up -d")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: nginx.py [--list|--ssl|--start|--stop|--check-configs|--backup-configs|--plan|--implement]")
        sys.exit(1)

    flag = sys.argv[1]
    
    if flag == '--list':
        list_domains()
    elif flag == '--ssl':
        if len(sys.argv) < 3:
            print("Specify an SSL action: get, check, or renew.")
        else:
            manage_ssl(sys.argv[2])
    elif flag == '--start':
        start_nginx()
    elif flag == '--stop':
        stop_nginx()
    elif flag == '--check-configs':
        check_configs()
    elif flag == '--backup-configs':
        backup_configs()
    elif flag == '--plan':
        plan_deployment()
    elif flag == '--implement':
        implement_deployment()
    else:
        print("Unknown flag.")
        sys.exit(1)
