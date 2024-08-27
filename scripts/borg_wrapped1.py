import subprocess
import os
import logging
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_remote_path(path):
    """Check if the path is a remote SSH path."""
    return ':' in path and '@' in path

def init_borg_repo(repo_path, encryption='none'):
    """Initialize a new Borg repository."""
    if not is_remote_path(repo_path) and not os.path.exists(os.path.dirname(repo_path)):
        return f"Error: The directory {os.path.dirname(repo_path)} does not exist."

    try:
        result = subprocess.run(
            ['borg', 'init', '--encryption', encryption, repo_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logging.info("Borg repository initialized successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error("Failed to initialize Borg repository.")
        return f"Error initializing repository: {e.stderr}"

def create_borg_backup(repo_path, backup_name, source_paths, exclude_patterns=None):
    """Create a backup with Borg."""
    if not is_remote_path(repo_path) and not os.path.exists(repo_path):
        return f"Error: The repository path {repo_path} does not exist."

    for path in source_paths:
        if not os.path.exists(path):
            return f"Error: The source path {path} does not exist."

    try:
        cmd = ['borg', 'create', f'{repo_path}::{backup_name}'] + source_paths
        if exclude_patterns:
            for pattern in exclude_patterns:
                cmd += ['--exclude', pattern]

        env = os.environ.copy()
        env['BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK'] = 'YES'

        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env/env
        )
        logging.info("Backup created successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error("Failed to create Borg backup.")
        return f"Error creating backup: {e.stderr}"

def list_borg_archives(repo_path):
    """List all archives in a Borg repository."""
    if not is_remote_path(repo_path) and not os.path.exists(repo_path):
        return f"Error: The repository path {repo_path} does not exist."

    try:
        result = subprocess.run(
            ['borg', 'list', repo_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logging.info("Listed archives successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error("Failed to list Borg archives.")
        return f"Error listing archives: {e.stderr}"

def restore_borg_backup(repo_path, archive_name, target_path, restore_paths=None):
    """Restore a Borg backup."""
    if not is_remote_path(repo_path) and not os.path.exists(repo_path):
        return f"Error: The repository path {repo_path} does not exist."

    if not os.path.exists(target_path):
        return f"Error: The target path {target_path} does not exist."

    try:
        cmd = ['borg', 'extract', f'{repo_path}::{archive_name}', '--destination', target_path]
        if restore_paths:
            cmd += restore_paths

        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logging.info("Backup restored successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error("Failed to restore Borg backup.")
        return f"Error restoring backup: {e.stderr}"

def check_borg_repo(repo_path):
    """Check the consistency of a Borg repository."""
    if not is_remote_path(repo_path) and not os.path.exists(repo_path):
        return f"Error: The repository path {repo_path} does not exist."

    try:
        result = subprocess.run(
            ['borg', 'check', repo_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logging.info("Borg repository checked successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error("Failed to check Borg repository.")
        return f"Error checking repository: {e.stderr}"

def main():
    parser = argparse.ArgumentParser(description="BorgBackup Python Wrapper")
    parser.add_argument('--init', help="Initialize a new Borg repository", action='store_true')
    parser.add_argument('--backup', help="Create a new backup", action='store_true')
    parser.add_argument('--list', help="List archives in a repository", action='store_true')
    parser.add_argument('--restore', help="Restore a backup", action='store_true')
    parser.add_argument('--check', help="Check the consistency of a Borg repository", action='store_true')

    args = parser.parse_args()

    if args.init:
        repo_path = input("Enter the repository path: ")
        encryption = input("Enter encryption type (default is 'none'): ") or 'none'
        print(init_borg_repo(repo_path, encryption))

    elif args.backup:
        repo_path = input("Enter the repository path: ")
        backup_name = input("Enter the name for the backup archive: ")
        source_paths = input("Enter the source paths to include, separated by spaces: ").split()
        exclude_patterns = input("Enter exclude patterns (optional), separated by spaces: ").split() or None
        print(create_borg_backup(repo_path, backup_name, source_paths, exclude_patterns))

    elif args.list:
        repo_path = input("Enter the repository path: ")
        print(list_borg_archives(repo_path))

    elif args.restore:
        repo_path = input("Enter the repository path: ")
        archive_name = input("Enter the archive name to restore: ")
        target_path = input("Enter the target path for restoration: ")
        restore_paths = input("Enter specific paths to restore (optional), separated by spaces: ").split() or None
        print(restore_borg_backup(repo_path, archive_name, target_path, restore_paths))

    elif args.check:
        repo_path = input("Enter the repository path: ")
        print(check_borg_repo(repo_path))
    else:
        print("Invalid action. Please choose a valid option.")

if __name__ == "__main__":
    main()
