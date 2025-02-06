#!/usr/bin/env python3
import json
import requests
import urllib3
from base64 import b64encode

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load configuration from file
with open('config.json') as config_file:
    config = json.load(config_file)

protocol = config.get('protocol', 'https')
host = config.get('host', 'localhost')
port = config.get('port', '55000')
user = config.get('user')
password = config.get('password')
login_endpoint = config.get('login_endpoint', 'security/user/authenticate')

login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
basic_auth = f"{user}:{password}".encode()
login_headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Basic {b64encode(basic_auth).decode()}'
}

print("\nLogin request ...\n")
response = requests.post(login_url, headers=login_headers, verify=False)
token = json.loads(response.content.decode())['data']['token']
print(token)

# New authorization header with the JWT we got
requests_headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {token}'
}

print("\n- API calls with TOKEN environment variable ...\n")
print("Getting API information:")

response = requests.get(f"{protocol}://{host}:{port}/?pretty=true", headers=requests_headers, verify=False)
print(response.text)

print("\nGetting agents status summary:")

response = requests.get(f"{protocol}://{host}:{port}/agents/summary/status?pretty=true", headers=requests_headers, verify=False)
print(response.text)

print("\nEnd of the script.\n")
