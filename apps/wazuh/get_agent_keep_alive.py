#!/usr/bin/env python3

import json
from base64 import b64encode

import requests  # To install requests, use: pip install requests
import urllib3

# Configuration
endpoint = '/agents?select=lastKeepAlive&select=id&status=disconnected'

protocol = config.get('protocol', 'https')
host = config.get('host', 'localhost')
port = config.get('port', '55000')
user = config.get('user')
password = config.get('password')

# Disable insecure https warnings (for self-signed SSL certificates)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Functions
def get_response(request_method, url, headers, verify=False, body=None):
    """Get API result"""
    if body is None:
        body = {}

    request_result = getattr(requests, request_method.lower())(url, headers=headers, verify=verify, data=body)

    if request_result.status_code == 200:
        return json.loads(request_result.content.decode())
    else:
        raise Exception(f"Error obtaining response: {request_result.json()}")

# Variables
base_url = f"{protocol}://{host}:{port}"
login_url = f"{base_url}/security/user/authenticate"
basic_auth = f"{user}:{password}".encode()
headers = {
           'Authorization': f'Basic {b64encode(basic_auth).decode()}',
           'Content-Type': 'application/json'
           }
headers['Authorization'] = f'Bearer {get_response("POST", login_url, headers)["data"]["token"]}'

# Request
response = get_response("GET", url=base_url + endpoint, headers=headers)

# WORK WITH THE RESPONSE AS YOU LIKE
print(json.dumps(response, indent=4, sort_keys=True))
