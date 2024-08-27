import subprocess
import os
import logging
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def init_borg_repo(repo_path, encryption='none'):
    """
    Initialize a new Borg repository.

    :param repo_path: Path to the repository (can be local or remote).
    :param encryption: Encryption mode, default is 'none'.
    :return: Command output or error message.
    """
    # Skip local path validation for remote paths
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

# Main function to trigger init (used when running as a script)
if __name__ == "__main__":
    action - input("Choose an action (init, backup): ").strip().lower()

    if action == "init":
        repo_path = input("Enter the repository path: ")
        encryption = input("Enter encryption type (default is 'none'): ") or 'none'
        print(init_borg_repo(repo_path, encryption))
    elif action == "backup":
        repo_path = input("Enter the repository path: ")
        backup_name = input("Enter the name for this backup: ")
        source_paths = input("Enter the paths to backup, separated by spaces: ").split()
        exclude_patterns = input("Enter paths to exclude, separated by spaces (optional): ").split() or None
        print(create_borg_backup(repo_path, backup_name, source_paths, exclude_patterns))
    else:
        print("Invalid action. Please choose 'init' or 'backup'.")



def create_borg_backup(repo_path, backup_name, source_paths, exclude_patterns=None):
    """
    Create a backup with Borg.

    :param repo_path: Path to the repository.
    :param backup_name: Name for the backup archive.
    :param source_paths: List of paths to include in the backup.
    :param exclude_patterns: List of exclude patterns (optional).
    :return: Command output or error message.
    """
    # Skip local path validation for remote paths
    try:
        cmd = ['borg', 'create', f'{repo_path}::{backup_name}'] + source_paths
        if exclude_patterns:
            for pattern in exclude_patterns:
                cmd += ['--exclude', pattern]

        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        logging.info("Backup created successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error("Failed to create Borg backup.")
        return f"Error creating backup: {e.stderr}"


def list_borg_archives(repo_path):
    if not os.path.exists(repo_path):
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
    if not os.path.exists(repo_path):
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
    if not os.path.exists(repo_path):
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
    
    if args.backup:
        repo_path = input("Enter the repository path: ")
        backup_name = input("Enter the name for the backup archive: ")
        source_paths = input("Enter the source paths to include, separated by spaces: ").split()
        exclude_patterns = input("Enter exclude patterns (optional), separated by spaces: ").split() or None
        print(create_borg_backup(repo_path, backup_name, source_paths, exclude_patterns))
    
    if args.list:
        repo_path = input("Enter the repository path: ")
        print(list_borg_archives(repo_path))
    
    if args.restore:
        repo_path = input("Enter the repository path: ")
        archive_name = input("Enter the archive name to restore: ")
        target_path = input("Enter the target path for restoration: ")
        restore_paths = input("Enter specific paths to restore (optional), separated by spaces: ").split() or None
        print(restore_borg_backup(repo_path, archive_name, target_path, restore_paths))
    
    if args.check:
        repo_path = input("Enter the repository path: ")
        print(check_borg_repo(repo_path))

if __name__ == "__main__":
    main()
