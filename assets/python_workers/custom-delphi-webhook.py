#!/usr/bin/env python3
# /var/ossec/integrations/custom-delphi-webhook.py
# root:wazuh 0750
# ─── Standard library ────────────────────────────────────────────────────────
import sys, json, os
from datetime import datetime 
from pathlib import Path

# third-party imports -------------------------------------------------------
try:
    import requests
    from dotenv import load_dotenv                 # lightweight helper
except ModuleNotFoundError as e:                   # pragma: no cover
    print(f"Missing dependency '{e.name}'. Run: pip install {e.name}")
    sys.exit(1)


# Error codes (Wazuh convention)
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7


BASE_DIR = Path(__file__).resolve().parent            # /var/ossec/integrations
load_dotenv(BASE_DIR / ".env")                        # loads HOOK_URL + WEBHOOK_TOKEN

HOOK_URL      = os.getenv("HOOK_URL")
WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN")

# FIXED: Use the correct Wazuh logs directory
LOG_FILE = '/var/ossec/logs/integrations.log'
debug_enabled = False


def debug(msg):
    """
    Append a line with an ISO-8601 timestamp (UTC) to integrations.log
    and echo to stdout when debug mode is on.
    """
    ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    line = f"{ts}  {msg}"

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as e:
        # fall back to stderr if the file can't be written
        print(f"[debug-fail] {e}: {line}", file=sys.stderr)

    if debug_enabled:
        print(line)


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

    # Add debugging to see what's happening
    debug(f"Script started with args: {args}")
    debug(f"Python executable: {sys.executable}")
    debug(f"Current working directory: {os.getcwd()}")
    debug(f"Script location: {__file__}")
    debug(f"BASE_DIR: {BASE_DIR}")
    debug(f"HOOK_URL from env: {HOOK_URL}")
    debug(f"WEBHOOK_TOKEN loaded: {'Yes' if WEBHOOK_TOKEN else 'No'}")

    if len(args) < 2:
        debug(f"# ERROR: Wrong arguments: {args}")
        sys.exit(ERR_BAD_ARGUMENTS)

    alert_file = args[1]
    hook_url   = HOOK_URL or os.getenv("OVERRIDE_HOOK_URL")  # env override
    api_key    = WEBHOOK_TOKEN or os.getenv("OVERRIDE_TOKEN")

    options_file = None

    if not hook_url or not api_key:
        debug("# ERROR: HOOK_URL or WEBHOOK_TOKEN not set – check .env")
        debug(f"# DEBUG: Looking for .env at: {BASE_DIR / '.env'}")
        debug(f"# DEBUG: .env exists: {(BASE_DIR / '.env').exists()}")
        sys.exit(ERR_BAD_ARGUMENTS)


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


    # LOG OUTGOING PAYLOAD - FIXED path
    PAYLOAD_DUMP_FILE = '/var/ossec/logs/sent_payload.log'
    try:
        with open(PAYLOAD_DUMP_FILE, 'a') as pf:
            ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
            pf.write(f"{ts}  " + json.dumps(body, indent=2) + '\n')
    except Exception as log_e:
        debug(f"Failed to log sent payload: {log_e}")

    headers = {
        "Content-Type": "application/json",
        "X-Auth-Token" : api_key
    }

    try:
        resp = requests.post(hook_url, headers=headers, data=json.dumps(body), timeout=10)
        resp.raise_for_status()
        debug(f"POST to {hook_url}: HTTP {resp.status_code}")
    except Exception as e:
        debug(f"Failed to POST to {hook_url}: {e}")
        sys.exit(2)


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
            sys.argv = [sys.argv[0], tf.name, "FAKE_API_KEY", "https://httpbin.org/post", "debug"]
            main(sys.argv)
    else:
        main(sys.argv)