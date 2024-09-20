import subprocess
import os
import logging
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

CONFIG_DIR = "/etc/eos/borg"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config")

def is_remote_path(path):
    """Check if the path is a remote SSH path."""
    return ':' in path and '@' in path

def ensure_config_directory():
    """Ensure that the config directory exists."""
    if not os.path.exists(CONFIG_DIR):
        try:
            os.makedirs(CONFIG_DIR)
            logging.info(f"Created configuration directory at {CONFIG_DIR}")
        except Exception as e:
            logging.error(f"Failed to create config directory: {e}")
            return False
    return True

def write_borg_config(repo_path, encryption):
    """Write the Borg repository configuration to a file."""
    if ensure_config_directory():
        try:
            with open(CONFIG_FILE, 'w') as config_file:
                config_file.write(f"REPO_PATH={repo_path}\n")
                config_file.write(f"ENCRYPTION={encryption}\n")
            logging.info(f"Borg configuration written to {CONFIG_FILE}")
        except Exception as e:
            logging.error(f"Failed to write Borg config: {e}")
    else:
        logging.error("Failed to ensure config directory, skipping config file creation.")

def load_borg_config():
    """Load Borg repository configuration from the config file."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as config_file:
                config = {}
                for line in config_file:
                    key, value = line.strip().split('=')
                    config[key] = value
                logging.info("Loaded Borg configuration.")
                return config
        except Exception as e:
            logging.error(f"Failed to load Borg config: {e}")
            return None
    else:
        logging.error("Configuration file does not exist.")
        return None

def check_or_ask_for_defaults():
    """Check if default configs exist or prompt user to input defaults."""
    config = load_borg_config()
    if config:
        print(f"Default configuration:\nREPO_PATH={config.get('REPO_PATH')}\nENCRYPTION={config.get('ENCRYPTION')}")
        return config
    else:
        # Ask for default values if config does not exist
        repo_path = input("Enter default repository path: ")
        encryption = input("Enter default encryption type (default is 'none'): ") or 'none'
        write_borg_config(repo_path, encryption)
        return {"REPO_PATH": repo_path, "ENCRYPTION": encryption}

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
        write_borg_config(repo_path, encryption)
        
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
            env=env
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
    parser.add_argument('--configs', help="Check or set default configuration", action='store_true')

    args = parser.parse_args()

    if args.configs:
        check_or_ask_for_defaults()

    elif args.init:
        config = check_or_ask_for_defaults()
        repo_path = config['REPO_PATH']
        encryption = config['ENCRYPTION']
        print(init_borg_repo(repo_path, encryption))

    elif args.backup:
        config = check_or_ask_for_defaults()
        repo_path = config['REPO_PATH']
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
        print("Try 'python3 borgWrapper.py --help'")

if __name__ == "__main__":
    main()
