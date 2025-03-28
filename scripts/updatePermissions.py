#!/usr/bin/env python3
import os
import stat
import sys
import argparse

def is_private_key(filepath):
    """
    Determine if the file is a private key.
    Uses filename heuristics and a peek into the file content.
    """
    basename = os.path.basename(filepath)
    # If the file does not end with ".pub" then treat it as a private key candidate.
    if not basename.endswith('.pub'):
        return True
    # Sometimes a private key may be misnamed with a .pub extension.
    try:
        with open(filepath, 'r') as f:
            header = f.read(200)
            if "PRIVATE KEY" in header:
                return True
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
    return False

def fix_ssh_permissions(directory):
    """
    Walk through the SSH directory and adjust permissions:
      - Private keys: mode 0o600
      - Public keys: mode 0o644 (unless they look like private keys)
      - Other files (like config, authorized_keys): generally mode 0o600
    """
    if not os.path.isdir(directory):
        print(f"Directory {directory} does not exist.", file=sys.stderr)
        return

    # Ensure the SSH directory itself is set to 700
    st = os.stat(directory)
    current_mode = stat.S_IMODE(st.st_mode)
    desired_mode = 0o700
    if current_mode != desired_mode:
        print(f"Fixing directory: {directory} (current: {oct(current_mode)}, setting to {oct(desired_mode)})")
        os.chmod(directory, desired_mode)
    else:
        print(f"No change needed for directory: {directory} (mode {oct(current_mode)})")

    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                st = os.stat(filepath)
                current_mode = stat.S_IMODE(st.st_mode)
                if is_private_key(filepath):
                    desired_mode = 0o600
                    file_type = "private key or secure file"
                else:
                    desired_mode = 0o644
                    file_type = "public key"
                if current_mode != desired_mode:
                    print(f"Fixing {file_type}: {filepath} (current: {oct(current_mode)}, setting to {oct(desired_mode)})")
                    os.chmod(filepath, desired_mode)
                else:
                    print(f"No change needed: {filepath} (mode {oct(current_mode)})")
            except Exception as e:
                print(f"Error processing {filepath}: {e}", file=sys.stderr)

def set_permission(path, desired_mode):
    """
    Set permission of a given file or directory if it doesn't match the desired_mode.
    """
    if os.path.exists(path):
        try:
            st = os.stat(path)
            current_mode = stat.S_IMODE(st.st_mode)
            if current_mode != desired_mode:
                print(f"Fixing {path} (current: {oct(current_mode)}, setting to {oct(desired_mode)})")
                os.chmod(path, desired_mode)
            else:
                print(f"No change needed: {path} (mode {oct(current_mode)})")
        except Exception as e:
            print(f"Error processing {path}: {e}", file=sys.stderr)
    else:
        print(f"Path {path} does not exist; skipping.")

def fix_ssl_private_permissions():
    """
    Ensure the /etc/ssl/private directory and its contents are secure.
      - Directory: mode 0o700
      - Files: mode 0o600
    """
    ssl_dir = "/etc/ssl/private"
    if os.path.isdir(ssl_dir):
        set_permission(ssl_dir, 0o700)
        for root, dirs, files in os.walk(ssl_dir):
            for d in dirs:
                set_permission(os.path.join(root, d), 0o700)
            for f in files:
                set_permission(os.path.join(root, f), 0o600)
    else:
        print(f"{ssl_dir} does not exist; skipping.")

def fix_system_permissions():
    """
    Fix permissions on critical system files and directories.
    """
    # Define a list of (path, desired_mode, description)
    items = [
        ("/root", 0o700, "root home directory"),
        ("/tmp", 0o1777, "temporary directory"),
        ("/etc/passwd", 0o644, "passwd file"),
        ("/etc/shadow", 0o640, "shadow file"),
        ("/etc/group", 0o644, "group file"),
        ("/etc/gshadow", 0o640, "gshadow file"),
        ("/etc/sudoers", 0o440, "sudoers file"),
        ("/etc/ssh/sshd_config", 0o600, "sshd_config file"),
        (os.path.expanduser("~/.ssh"), 0o700, "user SSH directory"),
    ]
    for path, mode, desc in items:
        print(f"Checking {desc}: {path}")
        set_permission(path, mode)

    # Fix /etc/ssl/private and its contents
    print("Checking SSL private keys directory: /etc/ssl/private")
    fix_ssl_private_permissions()

def main():
    parser = argparse.ArgumentParser(
        description="Fix SSH and critical system file permissions on Ubuntu."
    )
    parser.add_argument(
        "-d", "--directory", 
        default=os.path.expanduser("~/.ssh"),
        help="SSH directory to scan (default: ~/.ssh)"
    )
    parser.add_argument(
        "--system", action="store_true",
        help="Also fix system file and directory permissions."
    )
    args = parser.parse_args()

    print(f"Scanning SSH directory: {args.directory}")
    fix_ssh_permissions(args.directory)

    if args.system:
        print("\nApplying system permissions fixes...")
        fix_system_permissions()

if __name__ == '__main__':
    main()
