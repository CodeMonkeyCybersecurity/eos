#!/usr/bin/env python3
import os
import json
import requests
import urllib3

# Disable InsecureRequestWarning (useful if you're using self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = 'config.json'

def load_config():
    """Load configuration settings from config.json."""
    try:
        with open(CONFIG_FILE, 'r') as config_file:
            return json.load(config_file)
    except FileNotFoundError:
        print(f"Error: {CONFIG_FILE} not found.")
        exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing {CONFIG_FILE}: {e}")
        exit(1)

def save_config(config):
    """Write updated configuration settings back to config.json."""
    try:
        with open(CONFIG_FILE, 'w') as config_file:
            json.dump(config, config_file, indent=4)
    except Exception as e:
        print(f"Error writing to {CONFIG_FILE}: {e}")
        exit(1)

def confirm_config(config):
    """
    Confirm configuration with the user, allowing them to update values if necessary.
    The keys confirmed are: protocol, host, port, user, and password.
    """
    print("Current configuration:")
    keys = ['protocol', 'host', 'port', 'user', 'password']
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
    Authenticate to the Wazuh API using the credentials in config.json.
    Returns the new JWT token.
    """
    protocol = config.get('protocol')
    host = config.get('host')
    port = config.get('port')
    username = config.get('user')
    password = config.get('password')

    # Construct the URL for the authentication endpoint.
    url = f"{protocol}://{host}:{port}/security/user/auth"
    payload = {"username": username, "password": password}
    headers = {"Content-Type": "application/json"}

    print("Authenticating...")
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Authentication request failed: {e}")
        exit(1)

    if response.status_code != 200:
        print(f"Authentication failed ({response.status_code}): {response.text}")
        exit(1)

    # Expecting the token to be returned in the 'data' field.
    data = response.json()
    token = data.get("data")
    if not token:
        print("Failed to retrieve token from authentication response.")
        exit(1)

    print("Authentication successful. Retrieved new token.\n")
    return token

def get_user_details(config, token):
    """
    Retrieve details about the current user (including roles/permissions)
    from the Wazuh API using the provided JWT token.
    """
    protocol = config.get('protocol')
    host = config.get('host')
    port = config.get('port')
    username = config.get('user')
    url = f"{protocol}://{host}:{port}/security/users/{username}"

    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"User details request failed: {e}")
        exit(1)
    return response

def main():
    # Load configuration from file.
    config = load_config()
    
    # Confirm the configuration with the user (and update if necessary).
    config = confirm_config(config)

    # Check for an existing JWT token in the configuration.
    token = config.get("jwt_token")
    if not token:
        # If no token is stored, authenticate and save the new token.
        token = authenticate(config)
        config["jwt_token"] = token
        save_config(config)

    # Try to get user details with the stored token.
    response = get_user_details(config, token)
    if response.status_code == 401:
        # Token is invalid or expired; re-authenticate.
        print("Token is invalid or expired. Re-authenticating...")
        token = authenticate(config)
        config["jwt_token"] = token
        save_config(config)
        response = get_user_details(config, token)

    if response.status_code != 200:
        print(f"Error ({response.status_code}): {response.text}")
        exit(1)

    # Pretty-print the user information from the response.
    user_info = response.json()
    print("User Information:")
    print(json.dumps(user_info, indent=4))

if __name__ == "__main__":
    main()
