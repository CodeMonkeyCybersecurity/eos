#!/usr/bin/env python3
import os
import subprocess
import random
import sys

def run_command(cmd, description=""):
    """Run a shell command and print a description."""
    print(f"[*] {description}...")
    subprocess.run(cmd, shell=True, check=True)

def get_crontab():
    """Get current crontab entries; return empty string if none exist."""
    try:
        result = subprocess.check_output("crontab -l", shell=True, text=True)
    except subprocess.CalledProcessError:
        # No crontab for the current user (likely root)
        result = ""
    return result

def update_crontab(new_entries):
    """Update the crontab by appending new_entries."""
    current_cron = get_crontab()
    updated_cron = current_cron.strip() + "\n" + new_entries + "\n"
    proc = subprocess.Popen("crontab -", shell=True, stdin=subprocess.PIPE, text=True)
    proc.communicate(updated_cron)

def main():
    # Make sure the script is run as root
    if os.geteuid() != 0:
        print("[!] This script must be run as root. Please run with sudo or as root.")
        sys.exit(1)

    print("=== ClamAV Deployment and Scheduled Scan Setup ===\n")

    # 1. Update package lists and install ClamAV and its daemon
    run_command("apt-get update", "Updating package lists")
    run_command("apt-get install -y clamav clamav-daemon", "Installing ClamAV and ClamAV daemon")

    # 2. Stop the freshclam service to update virus definitions safely
    run_command("systemctl stop clamav-freshclam", "Stopping the freshclam service")

    # 3. Update ClamAV virus definitions
    run_command("freshclam", "Updating virus definitions")

    # 4. Restart the freshclam service
    run_command("systemctl start clamav-freshclam", "Starting the freshclam service")

    # 5. Ask the user which directories to scan (default: /home)
    default_dirs = "/home"
    user_input = input(f"Enter directories to scan (comma separated) [Default: {default_dirs}]: ").strip()
    if user_input == "":
        scan_dirs = default_dirs
    else:
        # Clean up and join directories with spaces (clamscan accepts multiple directories)
        dirs = [d.strip() for d in user_input.split(",") if d.strip()]
        scan_dirs = " ".join(dirs)
    print(f"[*] Directories to be scanned: {scan_dirs}")

    # 6. Create the daily scan script
    daily_scan_path = "/usr/local/bin/daily_clamav_scan.sh"
    daily_scan_content = f"""#!/bin/bash
#
# daily_clamav_scan.sh
#
# This script scans the following directories:
# {scan_dirs}
LOGFILE="/var/log/clamav/daily_scan.log"

# Ensure the log directory exists
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"

echo "Starting ClamAV scan at $(date)" | tee -a "$LOGFILE"

# Run ClamAV scan recursively on the specified directories.
# The '--infected' flag logs only infected files.
# The '--remove' flag automatically removes infected files.
clamscan -r {scan_dirs} --infected --log="$LOGFILE" --remove

echo "Completed ClamAV scan at $(date)" | tee -a "$LOGFILE"
"""
    print(f"[*] Creating daily scan script at {daily_scan_path}...")
    try:
        with open(daily_scan_path, "w") as f:
            f.write(daily_scan_content)
    except Exception as e:
        print(f"[!] Failed to write the daily scan script: {e}")
        sys.exit(1)

    # 7. Make the daily scan script executable
    run_command(f"chmod +x {daily_scan_path}", "Setting executable permissions on daily scan script")

    # 8. Schedule the daily scan script to run at a random time of day
    random_hour = random.randint(0, 23)
    random_minute = random.randint(0, 59)
    cron_line = f"{random_minute} {random_hour} * * * {daily_scan_path}"
    print(f"[*] Scheduling the scan script in cron to run daily at {random_hour:02d}:{random_minute:02d}...")
    update_crontab(cron_line)

    # 9. Final summary
    print("\n=== Deployment Complete ===")
    print("ClamAV has been installed and configured.")
    print(f"Daily scan script created at: {daily_scan_path}")
    print(f"Cron job scheduled to run daily at {random_hour:02d}:{random_minute:02d}")
    print("=============================")

if __name__ == "__main__":
    main()
