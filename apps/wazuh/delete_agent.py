#!/usr/bin/env python3
import json
import argparse
from base64 import b64encode
import requests
import urllib3

# Disable warnings for self-signed SSL certificates
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
    Confirm configuration with the user, allowing updates if necessary.
    Keys confirmed: protocol, host, port, user, and password.
    """
    keys = ['protocol', 'host', 'port', 'user', 'password']
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

def get_response(method, url, headers, verify=False, data=None):
    """
    Make an HTTP request with the specified method, URL, and headers,
    and return the parsed JSON response if the status code is 200.
    """
    try:
        response = getattr(requests, method.lower())(url, headers=headers, verify=verify, data=data)
    except Exception as e:
        print(f"Error during {method.upper()} request to {url}: {e}")
        exit(1)

    if response.status_code == 200:
        try:
            return response.json()
        except Exception as e:
            print(f"Error parsing JSON response: {e}")
            exit(1)
    else:
        print(f"Error obtaining response ({response.status_code}): {response.text}")
        exit(1)

def authenticate(config):
    """
    Authenticate to the Wazuh API using the credentials in config.json.
    Returns the JWT token retrieved from the API.
    """
    protocol = config.get('protocol')
    host = config.get('host')
    port = config.get('port')
    user = config.get('user')
    password = config.get('password')
    
    base_url = f"{protocol}://{host}:{port}"
    auth_url = f"{base_url}/security/user/authenticate?pretty=true"
    auth_payload = json.dumps({"username": user, "password": password})
    auth_headers = {'Content-Type': 'application/json'}
    
    print("\nAuthenticating...\n")
    result = get_response("POST", auth_url, auth_headers, verify=False, data=auth_payload)
    token = result.get('data', {}).get('token')
    if not token:
        print("Authentication failed: No token received.")
        exit(1)
    print("Authentication successful. Token received.")
    return token

def delete_agent(agent_id, token, config):
    """
    Delete the specified agent by ID using the provided JWT token.
    """
    protocol = config.get('protocol')
    host = config.get('host')
    port = config.get('port')
    base_url = f"{protocol}://{host}:{port}"
    delete_url = f"{base_url}/agents/{agent_id}?pretty=true"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    
    print(f"\nDeleting agent {agent_id}...\n")
    result = get_response("DELETE", delete_url, headers, verify=False)
    return result

def main():
    # Load and confirm configuration
    config = load_config()
    config = confirm_config(config)
    
    # Parse command-line arguments for the agent ID
    parser = argparse.ArgumentParser(
        description="Delete a Wazuh agent via the API by specifying its agent ID."
    )
    parser.add_argument("--agent-id", required=True, help="ID of the agent to delete")
    args = parser.parse_args()
    agent_id = args.agent_id

    # Authenticate to obtain a JWT token
    token = authenticate(config)
    config['jwt_token'] = token  # Save token for future reference if desired
    save_config(config)
    
    # Delete the specified agent
    result = delete_agent(agent_id, token, config)
    
    print("\nDeletion response:")
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()
