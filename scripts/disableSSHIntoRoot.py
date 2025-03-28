#!/usr/bin/env python3
import os
import sys
import subprocess

SSH_CONFIG_FILE = "/etc/ssh/sshd_config"

def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root. Try using sudo.", file=sys.stderr)
        sys.exit(1)

def backup_config():
    backup_file = SSH_CONFIG_FILE + ".bak"
    try:
        with open(SSH_CONFIG_FILE, "r") as f:
            config_data = f.read()
        with open(backup_file, "w") as f:
            f.write(config_data)
        print(f"Backup of SSH config created at {backup_file}")
    except Exception as e:
        print(f"Error creating backup of SSH config: {e}", file=sys.stderr)
        sys.exit(1)

def modify_config():
    try:
        with open(SSH_CONFIG_FILE, "r") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading SSH config file: {e}", file=sys.stderr)
        sys.exit(1)

    modified_lines = []
    found = False
    for line in lines:
        stripped = line.strip()
        # If we find a PermitRootLogin setting (even if commented), change it.
        if stripped.startswith("PermitRootLogin") or stripped.startswith("#PermitRootLogin"):
            modified_lines.append("PermitRootLogin no\n")
            found = True
        else:
            modified_lines.append(line)
    
    # If no PermitRootLogin line was found, add one at the end.
    if not found:
        modified_lines.append("\nPermitRootLogin no\n")
    
    try:
        with open(SSH_CONFIG_FILE, "w") as f:
            f.writelines(modified_lines)
        print("SSH configuration updated successfully.")
    except Exception as e:
        print(f"Error writing SSH config file: {e}", file=sys.stderr)
        sys.exit(1)

def restart_ssh_service():
    # Try several common commands to restart the SSH service.
    commands_to_try = [
        ["systemctl", "restart", "sshd"],
        ["systemctl", "restart", "ssh"],
        ["service", "sshd", "restart"],
        ["service", "ssh", "restart"]
    ]
    for cmd in commands_to_try:
        try:
            subprocess.run(cmd, check=True)
            print("SSH service restarted successfully using:", " ".join(cmd))
            return
        except Exception:
            continue
    print("Could not restart SSH service automatically. Please restart it manually.", file=sys.stderr)
    sys.exit(1)

def main():
    check_root()
    backup_config()
    modify_config()
    restart_ssh_service()

if __name__ == "__main__":
    main()
