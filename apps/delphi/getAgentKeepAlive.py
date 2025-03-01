#!/usr/bin/env python3
import json
from base64 import b64encode
import requests
import urllib3

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

def get_response(request_method, url, headers, verify=False, body=None):
    """Make an HTTP request and return the parsed JSON response."""
    if body is None:
        body = {}
    try:
        response = getattr(requests, request_method.lower())(url, headers=headers, verify=verify, data=body)
    except Exception as e:
        print(f"Error making {request_method.upper()} request to {url}: {e}")
        exit(1)

    if response.status_code == 200:
        try:
            return response.json()
        except Exception as e:
            print(f"Error parsing response: {e}")
            exit(1)
    else:
        print(f"Error obtaining response ({response.status_code}): {response.text}")
        exit(1)

def authenticate(config):
    """
    Authenticate to the Wazuh API using Basic Authentication.
    Returns the JWT token retrieved from the API.
    """
    protocol = config.get('protocol', 'https')
    host     = config.get('host', 'localhost')
    port     = config.get('port', '55000')
    user     = config.get('user')
    password = config.get('password')
    base_url = f"{protocol}://{host}:{port}"
    login_url = f"{base_url}/security/user/authenticate"

    basic_auth = f"{user}:{password}".encode()
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {b64encode(basic_auth).decode()}'
    }

    print("\nLogin request ...\n")
    result = get_response("POST", login_url, headers, verify=False)
    token = result.get("data", {}).get("token")
    if not token:
        print("Error: No token found in authentication response.")
        exit(1)

    print("Authentication successful. Token received.")
    return token

def main():
    # Load and confirm configuration
    config = load_config()
    config = confirm_config(config)

    # The endpoint to request (can also be added/modified in config.json)
    endpoint = config.get('endpoint', '/agents?select=lastKeepAlive&select=id&status=disconnected')

    protocol = config.get('protocol', 'https')
    host     = config.get('host', 'localhost')
    port     = config.get('port', '55000')
    base_url = f"{protocol}://{host}:{port}"

    # Authenticate to get the JWT token
    token = authenticate(config)

    # Save the token in configuration for future reference
    config['jwt_token'] = token
    save_config(config)

    # Setup headers for further API requests using the JWT token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    # Build full URL for the request and call the endpoint
    full_url = base_url + endpoint
    print(f"\nRequesting data from {full_url} ...\n")
    response = get_response("GET", full_url, headers, verify=False)

    # Work with the response as desired; here we pretty-print the JSON.
    print("Response:")
    print(json.dumps(response, indent=4, sort_keys=True))

if __name__ == "__main__":
    main()
