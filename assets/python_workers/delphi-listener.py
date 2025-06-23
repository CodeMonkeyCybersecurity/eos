#!/usr/bin/env python3
# /usr/local/bin/delphi-listener.py
# stanley:stanley 0750

"""
Minimal HTTP listener that replaces the old StackStorm webhook rule.

* Listens on 0.0.0.0:9000  (adjust in the systemd unit if you like)
* Accepts POST /wazuh_alert with a JSON body produced by Wazuh.
* Discards messages where body["rule"]["level"] <= 2.
* Pipes accepted JSON to /usr/local/bin/alert-to-db.py via STDIN.
* Appends accepted JSON (one-liner) to /var/log/stackstorm/wazuh-alerts.log.
"""

import json
import logging
import subprocess
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from dotenv import load_dotenv

LOG_PATH = "/var/log/stackstorm/wazuh-listener.log"
RAW_LOG_PATH = "/var/log/stackstorm/wazuh-alerts.log"
ALERT_LOADER = "/usr/local/bin/alert-to-db.py"
PORT = 9000           # change here or in the systemd ExecStart line

# Load environment variables
load_dotenv("/opt/stackstorm/packs/delphi/.env")

# Get authentication token from environment
WEBHOOK_AUTH_TOKEN = os.getenv('WEBHOOK_AUTH_TOKEN')
if not WEBHOOK_AUTH_TOKEN:
    logging.error("WEBHOOK_AUTH_TOKEN not set in environment. Authentication will be disabled!")
    print("WARNING: WEBHOOK_AUTH_TOKEN not set. Running without authentication!")
else:
    logging.info("Webhook authentication enabled")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/wazuh_alert":
            self.send_error(404, "Not Found")
            return

        # Check authentication if token is configured
        if WEBHOOK_AUTH_TOKEN:
            auth_header = self.headers.get('X-Auth-Token')
            if auth_header != WEBHOOK_AUTH_TOKEN:
                logging.warning("Unauthorized webhook attempt from %s", self.client_address[0])
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized'}).encode())
                return

        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length)
        try:
            body = json.loads(body_bytes)
        except json.JSONDecodeError as exc:
            logging.warning("Bad JSON: %s", exc)
            self.send_error(400, "Invalid JSON")
            return

        level = body.get("rule", {}).get("level", 0)
        if not isinstance(level, int):
            level = int(level) if str(level).isdigit() else 0

        if level <= 2:
            # Quietly accept but ignore low-level alerts
            self.send_response(204)      # No Content
            self.end_headers()
            return

        # --- hand off to alert-to-db ---
        try:
            subprocess.run(
                [ALERT_LOADER],
                input=json.dumps(body),
                check=True,
                text=True,
            )
            logging.info("Alert level %s forwarded to DB loader", level)
        except Exception as exc:
            logging.error("alert-to-db.py failed: %s", exc)

        # --- raw log dump (one line) ---
        try:
            with open(RAW_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(body, separators=(",", ":")) + "\n")
        except OSError as exc:
            logging.error("Could not append to %s: %s", RAW_LOG_PATH, exc)

        # Respond to Wazuh so it thinks everything is OK
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")

    # Silence the default noisy access log
    def log_message(self, fmt, *args):
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

if __name__ == "__main__":
    logging.info("Starting Wazuh webhook listener on port %d", PORT)
    try:
        ThreadedHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
    logging.info("Listener stopped")