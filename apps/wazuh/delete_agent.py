#!/usr/bin/env python3
import json
import requests
import argparse
from base64 import b64encode

# Disable warnings for self-signed SSL certificates if needed
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load configuration from file
with open('config.json') as config_file:
    config = json.load(config_file)

protocol = config.get('protocol')
host = config.get('host')
port = config.get('port')
user = config.get('user')
password = config.get('password')

# Set up argument parser
parser = argparse.ArgumentParser(
    description="Delete a Wazuh agent via the API by specifying its agent ID."
)
parser.add_argument("--agent-id", required=True, help="ID of the agent to delete")

# Parse the command-line arguments
args = parser.parse_args()
agent_id = args.agent_id

# Authentication endpoint and URL
auth_url = f"{protocol}://{host}:{port}/security/user/authenticate?pretty=true"

# Prepare the authentication payload
auth_payload = json.dumps({"username": user, "password": password})
auth_headers = {'Content-Type': 'application/json'}

# Authenticate
response = requests.post(auth_url, data=auth_payload, headers=auth_headers, verify=False)
if response.status_code != 200:
    print("Authentication failed:", response.text)
    exit(1)
token = response.json()['data']['token']

# Prepare headers for deletion
delete_headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {token}'
}

# Deletion URL
delete_url = f"{protocol}://{host}:{port}/agents/{agent_id}?pretty=true"

# Delete the agent
delete_response = requests.delete(delete_url, headers=delete_headers, verify=False)
result = delete_response.json()
print(json.dumps(result, indent=4))
