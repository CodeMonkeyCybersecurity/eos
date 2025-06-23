#!/usr/bin/env python3
# /var/ossec/integrations/custom-delphi-webhook.py
# root:wazuh 0750
import sys
import json
import os


try:
    import requests
except ImportError:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)  # ERR_NO_REQUEST_MODULE


# Error codes (Wazuh convention)
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7


pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f'{pwd}/logs/integrations.log'
debug_enabled = False


def debug(msg):
    with open(LOG_FILE, 'a') as f:
        f.write(msg + '\n')
    if debug_enabled:
        print(msg)


def get_json_file(file_path, is_options=False):
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


def main(args):
    global debug_enabled
    debug_enabled = False


    if len(args) < 4:
        debug(f"# ERROR: Wrong arguments: {args}")
        sys.exit(ERR_BAD_ARGUMENTS)


    alert_file = args[1]
    auth_token = args[2]  # X-Auth-Token for delphi-listener authentication
    hook_url = args[3]    # Should be http://your-delphi-host:9000/wazuh_alert
    options_file = None


    # Check for options file and debug
    for i in range(4, len(args)):
        if args[i].endswith('options'):
            options_file = args[i]
        if args[i] == 'debug':
            debug_enabled = True


    alert_json = get_json_file(alert_file)
    options_json = get_json_file(options_file, is_options=True) if options_file else {}


    # Prepare message body
    body = alert_json
    if options_json:
        body.update(options_json)


    # LOG OUTGOING PAYLOAD
    PAYLOAD_DUMP_FILE = f'{pwd}/logs/sent_payload.log'
    try:
        with open(PAYLOAD_DUMP_FILE, 'a') as pf:
            pf.write(json.dumps(body, indent=2) + '\n')
    except Exception as log_e:
        debug(f"Failed to log sent payload: {log_e}")


    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token": auth_token
    }


    try:
        resp = requests.post(hook_url, headers=headers, data=json.dumps(body), timeout=10)
        resp.raise_for_status()
        debug(f"POST to {hook_url}: HTTP {resp.status_code}")
    except Exception as e:
        debug(f"Failed to POST to {hook_url}: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv)


if __name__ == "__main__":
    if "--test" in sys.argv:
        # Example test: send known alert to a test URL
        import tempfile
        test_payload = {
            "timestamp": "2025-06-02T21:47:23.199+0800",
            "rule": {"level": 3, "description": "Test Docker alert"},
            "agent": {"id": "test", "name": "testagent", "ip": "1.2.3.4"},
            "manager": {"name": "testmgr"},
            "id": "12345",
            "decoder": {"name": "json"},
            "data": {"integration": "docker"},
            "location": "Wazuh-Docker"
        }
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            json.dump(test_payload, tf)
            tf.flush()
            # Call main() with fake args
            sys.argv = [sys.argv[0], tf.name, "FAKE_AUTH_TOKEN", "http://localhost:9000/wazuh_alert", "debug"]
            main(sys.argv)
    else:
        main(sys.argv)
