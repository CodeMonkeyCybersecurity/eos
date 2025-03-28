#!/usr/bin/env python3
import random
import subprocess

# Generate random hour (0-23) and minute (0-59)
hour = random.randint(0, 23)
minute = random.randint(0, 59)

# Define the command you want to run.
# Adjust the full path if needed (use 'which yum' to verify yum's path).
command = "/usr/bin/yum update -y && /usr/bin/yum autoremove -y && /usr/bin/yum clean all"

# Construct the cron line.
cron_line = f"{minute} {hour} * * * {command}\n"

# Fetch existing crontab entries.
try:
    current_cron = subprocess.check_output(
        ["crontab", "-l"], stderr=subprocess.STDOUT, text=True
    )
except subprocess.CalledProcessError:
    # If no crontab exists, start with an empty string.
    current_cron = ""

# Append the new cron entry.
new_cron = current_cron + cron_line

# Install the new crontab.
process = subprocess.run(["crontab", "-"], input=new_cron, text=True)

if process.returncode == 0:
    print("Cron job added successfully!")
    print(f"Scheduled daily at {hour:02d}:{minute:02d}.")
else:
    print("Failed to update crontab.")
