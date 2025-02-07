#!/usr/bin/env python3
import os
import json
import requests
import urllib3

# Load configuration from file
with open('config.json') as config_file:
    config = json.load(config_file)

# Extract configuration values
protocol = config.get('protocol')
host = config.get('host')
port = config.get('port')
user = config.get('user')
password = config.get('password')

# Get the token from the environment variable
TOKEN = os.environ.get("TOKEN")
if not TOKEN:
    print("Error: Please set the TOKEN environment variable with your JWT token.")
    print("")
    print("Tip: run wazuh_api_authenticator.py")
    exit(1)

# Build the URL for the user details endpoint
url = f"https://{WAZUH_HOST}:{WAZUH_PORT}/security/users/{USERNAME}"

headers = {
    "Authorization": f"Bearer {TOKEN}"
}

print("Requesting current user details...\n")
try:
    response = requests.get(url, headers=headers, verify=False)
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")
    exit(1)

if response.status_code != 200:
    print(f"Error ({response.status_code}): {response.text}")
else:
    # Pretty-print the JSON response, which should include the user's roles and permissions
    user_info = response.json()
    print("User Information:")
    print(json.dumps(user_info, indent=4))
