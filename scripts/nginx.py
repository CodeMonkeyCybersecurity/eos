#!/usr/bin/env python3

import os
import subprocess
import shutil
import sys
import yaml

NGINX_DIR = os.path.expanduser('~/nginx-docker')
DOCKER_COMPOSE_FILE = os.path.join(NGINX_DIR, 'docker-compose.yaml')
BACKUP_DIR = '/etc/eos/nginx-docker'
LOG_DIR = '/var/log/eos/nginx-docker'

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, 'nginx.log')

def log_message(message):
    """Logs a message to the log file."""
    with open(LOG_FILE, 'a') as log:
        log.write(f"{message}\n")
    print(message)

def run_command(command):
    """Runs a shell command and returns the output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        log_message(f"Command '{command}' executed successfully.")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        log_message(f"Error running command: {command}")
        log_message(e.output)
        sys.exit(1)

def list_domains():
    """Lists domains and subdomains."""
    if os.path.exists(DOCKER_COMPOSE_FILE):
        with open(DOCKER_COMPOSE_FILE, 'r') as f:
            config = yaml.safe_load(f)
            if 'services' in config and 'nginx' in config['services']:
                log_message("Domains and subdomains in Nginx config:")
                for domain in config['services']['nginx'].get('domains', []):
                    log_message(f"- {domain}")
            else:
                log_message("No domains found in Nginx service.")
    else:
        log_message(f"{DOCKER_COMPOSE_FILE} not found!")

def manage_ssl(action):
    """Manages SSL certificates."""
    if action == 'get':
        log_message("Fetching SSL certificates...")
        run_command("certbot certonly --nginx")
    elif action == 'check':
        log_message("Checking SSL certificates...")
        run_command("certbot certificates")
    elif action == 'renew':
        log_message("Renewing SSL certificates...")
        run_command("certbot renew")
    else:
        log_message("Unknown SSL action. Use 'get', 'check', or 'renew'.")

def start_nginx():
    """Starts Nginx."""
    log_message("Starting Nginx...")
    run_command(f"docker-compose -f {DOCKER_COMPOSE_FILE} up -d")

def stop_nginx():
    """Stops Nginx."""
    log_message("Stopping Nginx...")
    run_command(f"docker-compose -f {DOCKER_COMPOSE_FILE} down")

def check_configs():
    """Checks Nginx configurations."""
    log_message("Checking Nginx configurations...")
    run_command(f"docker-compose -f {DOCKER_COMPOSE_FILE} config")

def backup_configs():
    """Backs up Nginx configurations."""
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    log_message(f"Backing up Nginx configs to {BACKUP_DIR}...")
    shutil.copy(DOCKER_COMPOSE_FILE, BACKUP_DIR)
    log_message("Backup completed.")

def plan_deployment():
    """Plans the deployment of Nginx on Docker."""
    log_message("Planning Nginx deployment...")
    # You can expand this with more detailed planning logic if needed.
    log_message(f"Deploying to: {NGINX_DIR}")
    log_message(f"Docker Compose File: {DOCKER_COMPOSE_FILE}")

def implement_deployment():
    """Implements the planned Nginx deployment."""
    log_message("Implementing Nginx deployment...")
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
    
    log_message(f"Docker Compose file created at {DOCKER_COMPOSE_FILE}.")
    log_message("Starting Nginx deployment...")
    run_command(f"docker-compose -f {DOCKER_COMPOSE_FILE} up -d")

def get_user_input(prompt):
    """Gets input from the user."""
    return input(prompt)

def check_if_configured(subdomain, port):
    """Checks if the subdomain and port are already configured."""
    if os.path.exists(DOCKER_COMPOSE_FILE):
        with open(DOCKER_COMPOSE_FILE, 'r') as f:
            config = yaml.safe_load(f)
            nginx_config = config.get('services', {}).get('nginx', {})
            domains = nginx_config.get('domains', [])
            ports = nginx_config.get('ports', [])
            if subdomain in domains or any(str(port) in p for p in ports):
                log_message(f"Error: Subdomain '{subdomain}' or port '{port}' is already configured.")
                sys.exit(1)

def connect_plan():
    """Plans the Nginx reverse proxy setup."""
    subdomain = get_user_input("Enter the subdomain: ")
    port = get_user_input("Enter the port to listen on: ")
    
    log_message(f"Planning Nginx reverse proxy for subdomain: {subdomain} on port: {port}")
    check_if_configured(subdomain, port)
    log_message(f"Subdomain and port are available for configuration.")

def connect_implement():
    """Implements the Nginx reverse proxy setup."""
    subdomain = get_user_input("Enter the subdomain: ")
    port = get_user_input("Enter the port to listen on: ")
    
    check_if_configured(subdomain, port)
    
    if os.path.exists(DOCKER_COMPOSE_FILE):
        with open(DOCKER_COMPOSE_FILE, 'r') as f:
            config = yaml.safe_load(f)
            nginx_config = config.get('services', {}).get('nginx', {})
            nginx_config.setdefault('domains', []).append(subdomain)
            nginx_config.setdefault('ports', []).append(f"{port}:{port}")
            config['services']['nginx'] = nginx_config
        
        with open(DOCKER_COMPOSE_FILE, 'w') as f:
            yaml.safe_dump(config, f)
        
        log_message(f"Nginx reverse proxy implemented for subdomain: {subdomain} on port: {port}")
    
    backup_configs()

def connect_check():
    """Checks the reverse proxy setup."""
    log_message("Checking Nginx reverse proxy configuration...")
    check_configs()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        log_message("Usage: nginx.py [--list|--ssl|--start|--stop|--check-configs|--backup-configs|--plan|--implement|--connect-plan|--connect-implement|--connect-check]")
        sys.exit(1)

    flag = sys.argv[1]
    
    if flag == '--list':
        list_domains()
    elif flag == '--ssl':
        if len(sys.argv) < 3:
            log_message("Specify an SSL action: get, check, or renew.")
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
    elif flag == '--connect-plan':
        connect_plan()
    elif flag == '--connect-implement':
        connect_implement()
    elif flag == '--connect-check':
        connect_check()
    else:
        log_message("Unknown flag.")
        sys.exit(1)
