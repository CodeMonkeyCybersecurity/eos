#!/usr/bin/env python3
import os
import stat
import sys

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

def fix_permissions(directory):
    """
    Walk through the directory and adjust permissions:
      - Private keys: mode 0o600
      - Public keys: mode 0o644 (unless they look like private keys)
    """
    if not os.path.isdir(directory):
        print(f"Directory {directory} does not exist.", file=sys.stderr)
        return

    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                st = os.stat(filepath)
                current_mode = stat.S_IMODE(st.st_mode)
                if is_private_key(filepath):
                    desired_mode = 0o600
                    file_type = "private"
                else:
                    desired_mode = 0o644
                    file_type = "public"
                if current_mode != desired_mode:
                    print(f"Fixing {file_type} key: {filepath} (current: {oct(current_mode)}, setting to {oct(desired_mode)})")
                    os.chmod(filepath, desired_mode)
                else:
                    print(f"No change needed: {filepath} (mode {oct(current_mode)})")
            except Exception as e:
                print(f"Error processing {filepath}: {e}", file=sys.stderr)

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Fix SSH key file permissions (private keys to 600, public keys to 644)."
    )
    parser.add_argument(
        "-d", "--directory", 
        default=os.path.expanduser("~/.ssh"),
        help="Directory to scan (default: ~/.ssh)"
    )
    args = parser.parse_args()

    print(f"Scanning directory: {args.directory}")
    fix_permissions(args.directory)

if __name__ == '__main__':
    main()
