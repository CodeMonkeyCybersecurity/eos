// cmd/create/wazuh_templates.go
// Embedded templates for Wazuh integration scripts

package create

func getCustomIrisShellScript() string {
	return `#!/bin/sh
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# Modified for Iris integration by Code Monkey Cybersecurity
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/$(echo ${SCRIPT_NAME} | sed 's/\-/_/g').py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

        PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac

${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
`
}

func getCustomIrisPythonScript() string {
	return `#!/usr/bin/env python3
"""
Wazuh Iris Integration
Sends Wazuh alerts to Iris webhook for AI-powered analysis

Created by Code Monkey Cybersecurity
ABN: 77 177 673 061
Motto: "Cybersecurity. With humans."
"""

import sys
import json
import os
from datetime import datetime
from pathlib import Path

# third-party imports
try:
    import requests
    from dotenv import load_dotenv
except ModuleNotFoundError as e:
    print(f"Missing dependency '{e.name}'. Run: pip install {e.name}")
    sys.exit(1)

# Error codes (Wazuh convention)
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

# Configuration
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

HOOK_URL = os.getenv("HOOK_URL")
WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN")
LOG_FILE = '/var/ossec/logs/integrations.log'
PAYLOAD_LOG = '/var/ossec/logs/sent_payload.log'

debug_enabled = False


def debug(msg):
    """Log message with timestamp to integrations.log"""
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    line = f"{ts}  {msg}"

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        print(f"[debug-fail] {e}: {line}", file=sys.stderr)

    if debug_enabled:
        print(line)


def get_json_file(file_path, is_options=False):
    """Load JSON from file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        debug(f"# JSON file {file_path} doesn't exist")
        if not is_options:
            sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug(f"Failed decoding JSON in {file_path}: {e}")
        sys.exit(ERR_INVALID_JSON)
    return {}


def log_payload(payload):
    """Log outgoing payload for debugging"""
    try:
        with open(PAYLOAD_LOG, 'a') as pf:
            ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            pf.write(f"{ts}  " + json.dumps(payload, indent=2) + '\n')
    except Exception as e:
        debug(f"Failed to log payload: {e}")


def send_to_webhook(alert_data, hook_url, auth_token):
    """Send alert to Iris webhook"""
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": auth_token
    }

    try:
        resp = requests.post(
            hook_url,
            headers=headers,
            data=json.dumps(alert_data),
            timeout=10
        )
        resp.raise_for_status()
        debug(f"POST to {hook_url}: HTTP {resp.status_code}")
        return True
    except requests.exceptions.RequestException as e:
        debug(f"Failed to POST to {hook_url}: {e}")
        return False


def main(args):
    global debug_enabled

    # Check for debug flag
    debug_enabled = 'debug' in args

    debug(f"# Iris integration started")
    debug(f"# Args: {args}")
    debug(f"# Script: {__file__}")
    debug(f"# BASE_DIR: {BASE_DIR}")

    # Validate arguments
    if len(args) < 2:
        debug(f"# ERROR: Wrong arguments: {args}")
        sys.exit(ERR_BAD_ARGUMENTS)

    alert_file = args[1]

    # Load environment variables
    hook_url = HOOK_URL or os.getenv("OVERRIDE_HOOK_URL")
    auth_token = WEBHOOK_TOKEN or os.getenv("OVERRIDE_TOKEN")

    if not hook_url or not auth_token:
        debug("# ERROR: HOOK_URL or WEBHOOK_TOKEN not set in .env")
        debug(f"# .env location: {BASE_DIR / '.env'}")
        debug(f"# .env exists: {(BASE_DIR / '.env').exists()}")
        sys.exit(ERR_BAD_ARGUMENTS)

    debug(f"# HOOK_URL: {hook_url}")
    debug(f"# TOKEN configured: Yes")

    # Check for options file
    options_file = None
    for i in range(4, len(args)):
        if args[i].endswith('options'):
            options_file = args[i]

    # Load alert data
    alert_json = get_json_file(alert_file)
    options_json = get_json_file(options_file, is_options=True) if options_file else {}

    # Merge alert with options
    body = alert_json
    if options_json:
        body.update(options_json)

    # Log payload
    log_payload(body)

    # Send to webhook
    success = send_to_webhook(body, hook_url, auth_token)

    if success:
        debug(f"# Alert sent successfully")
        sys.exit(0)
    else:
        debug(f"# Failed to send alert")
        sys.exit(2)


if __name__ == "__main__":
    if "--test" in sys.argv:
        # Test mode
        import tempfile
        test_payload = {
            "timestamp": "2025-10-07T12:00:00.000+0800",
            "rule": {"level": 10, "description": "Test alert", "id": "999999"},
            "agent": {"id": "000", "name": "test", "ip": "shared.GetInternalHostname"},
            "manager": {"name": "test"},
            "data": {
                "vulnerability": {
                    "severity": "Critical",
                    "package": {"name": "test-package"},
                    "title": "Test Alert"
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            json.dump(test_payload, tf)
            tf.flush()
            sys.argv = [sys.argv[0], tf.name, "debug"]
            main(sys.argv)
    else:
        main(sys.argv)
`
}
