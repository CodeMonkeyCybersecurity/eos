#!/usr/bin/env python3
import os
import subprocess
import sys

SERVICE_PATH = "/etc/systemd/system/whois.service"
SERVICE_CONTENT = """[Unit]
Description=WHOIS Lookup Script Service
After=network.target

[Service]
Type=notify
User=root
WorkingDirectory=/opt/eos/scripts
ExecStart=/opt/whois/venv/bin/python3 /opt/eos/scripts/whois.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

def write_service_file():
    try:
        with open(SERVICE_PATH, "w") as f:
            f.write(SERVICE_CONTENT)
        print(f"Service file written to {SERVICE_PATH}")
    except Exception as e:
        print(f"Failed to write service file: {e}")
        sys.exit(1)

def reload_daemon():
    try:
        subprocess.check_call(["systemctl", "daemon-reload"])
        print("systemctl daemon-reload completed")
    except subprocess.CalledProcessError as e:
        print(f"Error reloading systemd daemon: {e}")
        sys.exit(1)

def start_service():
    try:
        subprocess.check_call(["systemctl", "start", "whois.service"])
        print("whois.service started")
    except subprocess.CalledProcessError as e:
        print(f"Error starting whois.service: {e}")
        sys.exit(1)

def enable_service():
    try:
        subprocess.check_call(["systemctl", "enable", "whois.service"])
        print("whois.service enabled to start at boot")
    except subprocess.CalledProcessError as e:
        print(f"Error enabling whois.service: {e}")
        sys.exit(1)

def main():
    # Check if script is running as root
    if os.geteuid() != 0:
        print("This script must be run as root. Exiting.")
        sys.exit(1)

    write_service_file()
    reload_daemon()
    start_service()
    enable_service()
    print("WHOIS Lookup Script Service deployed successfully.")

if __name__ == "__main__":
    main()
