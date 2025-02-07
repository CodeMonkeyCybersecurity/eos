#!/usr/bin/env python3
import json
import requests
import urllib3
from base64 import b64encode

# Disable insecure HTTPS warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = 'config.json'

def load_config():
    """Load configuration settings from config.json."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading configuration: {e}")
        exit(1)

def save_config(config):
    """Write updated configuration settings back to config.json."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Error saving configuration: {e}")
        exit(1)

def confirm_config(config):
    """
    Confirm configuration with the user, allowing them to update values if necessary.
    Keys confirmed: protocol, host, port, user, password, and login_endpoint.
    """
    keys = ['protocol', 'host', 'port', 'user', 'password', 'login_endpoint']
    print("Current configuration:")
    for key in keys:
        print(f"  {key}: {config.get(key)}")
    answer = input("Are these values correct? (y/n): ").strip().lower()
    if answer != 'y':
        print("Enter new values (press Enter to keep the current value):")
        for key in keys:
            current_value = config.get(key)
            new_value = input(f"  {key} [{current_value}]: ").strip()
            if new_value:
                config[key] = new_value
        save_config(config)
        print("Configuration updated.\n")
    return config

def authenticate(config):
    """
    Authenticate to the Wazuh API using Basic Authentication.
    Returns the JWT token retrieved from the API.
    """
    protocol      = config.get('protocol', 'https')
    host          = config.get('host', 'localhost')
    port          = config.get('port', '55000')
    user          = config.get('user')
    password      = config.get('password')
    login_endpoint= config.get('login_endpoint', 'security/user/authenticate')
    
    login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
    basic_auth = f"{user}:{password}".encode()
    login_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {b64encode(basic_auth).decode()}'
    }

    print("\nLogin request ...\n")
    try:
        response = requests.post(login_url, headers=login_headers, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Login request failed: {e}")
        exit(1)

    if response.status_code != 200:
        print(f"Login failed ({response.status_code}): {response.text}")
        exit(1)

    try:
        token = response.json()['data']['token']
    except Exception as e:
        print(f"Error parsing login response: {e}")
        exit(1)

    print("Token received:\n", token)
    return token

def get_api_info(config, token):
    """
    Retrieve API information from the Wazuh API.
    """
    protocol = config.get('protocol', 'https')
    host     = config.get('host', 'localhost')
    port     = config.get('port', '55000')
    url      = f"{protocol}://{host}:{port}/?pretty=true"
    headers  = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    
    print("\nGetting API information:\n")
    try:
        response = requests.get(url, headers=headers, verify=False)
        print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving API information: {e}")

def get_agents_status(config, token):
    """
    Retrieve the agents status summary from the Wazuh API.
    """
    protocol = config.get('protocol', 'https')
    host     = config.get('host', 'localhost')
    port     = config.get('port', '55000')
    url      = f"{protocol}://{host}:{port}/agents/summary/status?pretty=true"
    headers  = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    
    print("\nGetting agents status summary:\n")
    try:
        response = requests.get(url, headers=headers, verify=False)
        print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error retrieving agents status summary: {e}")

def main():
    # Load and confirm configuration
    config = load_config()
    config = confirm_config(config)

    # Authenticate and get a JWT token
    token = authenticate(config)

    # Save the token into configuration for future reference
    config['jwt_token'] = token
    save_config(config)

    # Perform API calls using the token
    get_api_info(config, token)
    get_agents_status(config, token)

    print("\nEnd of the script.\n")

if __name__ == "__main__":
    main()
