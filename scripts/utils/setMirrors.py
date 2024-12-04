#!/usr/bin/env python3

import os
import shutil
import datetime
import subprocess

def main():
    sources_file = '/etc/apt/sources.list.d/ubuntu.sources'

    # Check if the sources file exists
    if os.path.exists(sources_file):
        # Create backup filename with timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
        backup_file = f'/etc/apt/sources.list.d/ubuntu.sources_{timestamp}.bak'
        try:
            # Backup the current sources file
            shutil.copy2(sources_file, backup_file)
            print(f"Backed up {sources_file} to {backup_file}")
        except Exception as e:
            print(f"Error backing up file: {e}")
            return
        try:
            # Delete the current sources file
            os.remove(sources_file)
            print(f"Deleted {sources_file}")
        except Exception as e:
            print(f"Error deleting file: {e}")
            return
    else:
        print(f"{sources_file} does not exist. Proceeding to create a new one.")

    # Contents to write to the new sources file
    new_contents = """Types: deb deb-src
URIs: http://au.archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb deb-src
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
"""

    try:
        # Write the new contents to the sources file
        with open(sources_file, 'w') as f:
            f.write(new_contents)
        print(f"Created new {sources_file} with specified contents.")
    except Exception as e:
        print(f"Error writing to file: {e}")
        return

    # Run apt update
    try:
        print("Running 'apt update'...")
        subprocess.run(['apt', 'update'], check=True)
        print("apt update completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error running 'apt update': {e}")
        return

if __name__ == '__main__':
    main()
