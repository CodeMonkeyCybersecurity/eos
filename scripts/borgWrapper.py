import yaml
import os
import subprocess
import argparse
import logging

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    """Load configuration from YAML file."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as file:
                config = yaml.safe_load(file)
                logging.info("Configuration loaded successfully.")
                return config
        except yaml.YAMLError as e:
            logging.error(f"Error loading configuration file: {e}")
            return None
    else:
        logging.error(f"Configuration file not found. Please run 'sudo python3 configureBorg.py --create'.")
        return None

def check_yaml(config):
    """Check if YAML config has valid values."""
    required_values = {
        'borg.repo': config.get('borg', {}).get('repo'),
        'borg.passphrase': config.get('borg', {}).get('passphrase'),
        'backup.encryption': config.get('backup', {}).get('encryption'),
        'backup.paths_to_backup': config.get('backup', {}).get('paths_to_backup')
    }

    for key, value in required_values.items():
        if not value:
            logging.error(f"Configuration issue: '{key}' is not set or is invalid.")
            return False
    logging.info("All required configuration values are set.")
    return True

def check_repo(config):
    """Check repository health with 'borg check'."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']

    # Set the environment variable for passphrase
    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    try:
        result = subprocess.run(['borg', 'check', repo], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Repository check failed: {e.stderr}")
        return False

def run_borg_backup(config, dryrun=False):
    """Run the Borg backup using the configuration values."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']
    paths = config['backup']['paths_to_backup']

    # Set the environment variable for passphrase
    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    # Build the borg create command
    borg_create_cmd = ['borg', 'create', f'{repo}::{{hostname}}-{{now}}'] + paths + [
        '--verbose',
        '--filter', config['backup']['filter'],
        '--list',
        '--stats',
        '--show-rc',
        '--compression', config['backup']['compression'],
        '--exclude-caches'
    ]

    # Add any exclude patterns from config
    for pattern in config['backup'].get('exclude_patterns', []):
        borg_create_cmd += ['--exclude', pattern]

    # Add dry-run if specified
    if dryrun:
        borg_create_cmd.append('--dry-run')

    try:
        # Run the borg create command
        result = subprocess.run(borg_create_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Borg backup failed: {e.stderr}")

def list_borg_archives(config):
    """List all archives in the Borg repository."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']

    # Set the environment variable for passphrase
    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    try:
        result = subprocess.run(['borg', 'list', repo], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Listing archives failed: {e.stderr}")

def restore_borg_archive(config, archive_name, target_dir):
    """Restore a Borg archive to a specified directory."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']

    # Set the environment variable for passphrase
    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    borg_restore_cmd = ['borg', 'extract', f'{repo}::{archive_name}', '--target', target_dir]

    try:
        # Run the borg restore command
        result = subprocess.run(borg_restore_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(f"Restored archive '{archive_name}' to '{target_dir}'")
    except subprocess.CalledProcessError as e:
        logging.error(f"Restoring archive failed: {e.stderr}")

def test_restore_borg_archive(config, archive_name):
    """Perform a test restore without actually extracting the files."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']

    # Set the environment variable for passphrase
    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    borg_test_restore_cmd = ['borg', 'extract', '--dry-run', f'{repo}::{archive_name}']

    try:
        # Run the test restore command
        result = subprocess.run(borg_test_restore_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(f"Test restore of archive '{archive_name}' succeeded.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Test restore failed: {e.stderr}")

def print_help():
    """Print available flags and their descriptions."""
    help_message = """
Available Flags:
--check-yaml       : Check the YAML configuration for missing values
--check-repo       : Check the Borg repository health
--dryrun           : Perform a dry-run of the backup without making changes
--list             : List all Borg archives in the repository
--restore          : Restore a specific archive (requires --target-dir)
--test-restore     : Test restore a specific archive without extracting
--target-dir       : Specify the target directory for restoring archives
"""
    print(help_message)

def interactive_prompt():
    """Interactive prompt if no flags are provided."""
    print("No argument provided. Would you like to run --help? [y/n]")
    choice = input().lower()

    if choice == 'y':
        print_help()
        retry = input("Would you like to retry with a valid argument? [y/n]: ").lower()
        if retry == 'y':
            print("Please re-run the script with a valid argument.")
        else:
            print("Exiting...")
    else:
        print("Exiting...")

def main():
    parser = argparse.ArgumentParser(description="Borg Backup Wrapper", add_help=True)  # Use default argparse help
    parser.add_argument('--check-yaml', help="Check the YAML configuration", action='store_true')
    parser.add_argument('--check-repo', help="Check the Borg repository", action='store_true')
    parser.add_argument('--dryrun', help="Run a dry run of the backup", action='store_true')
    parser.add_argument('--list', help="List all archives in the repository", action='store_true')
    parser.add_argument('--restore', help="Restore a specific archive", type=str)
    parser.add_argument('--test-restore', help="Test restore a specific archive", type=str)
    parser.add_argument('--target-dir', help="Specify the target directory for the restore", type=str)

    args = parser.parse_args()

    # If no arguments are passed, prompt the user for help or exit
    if not any(vars(args).values()):
        interactive_prompt()
        return

    # Load the YAML configuration
    config = load_config()
    if not config:
        return  # Exit if the config file is not found

    # Handle flags
    if args.check_yaml:
        if check_yaml(config):
            logging.info("YAML configuration is valid.")
        else:
            logging.error("YAML configuration has issues.")
        return

    if args.check_repo:
        if check_repo(config):
            logging.info("Repository check passed.")
        else:
            logging.error("Repository check failed.")
        return

    if args.dryrun:
        logging.info("Running a dry run of the backup.")
        run_borg_backup(config, dryrun=True)
        return

    if args.list:
        logging.info("Listing all Borg archives.")
        list_borg_archives(config)
        return

    if args.restore:
        if not args.target_dir:
            logging.error("Target directory must be specified for restoration.")
        else:
            logging.info(f"Restoring archive '{args.restore}' to '{args.target_dir}'.")
            restore_borg_archive(config, args.restore, args.target_dir)
        return

    if args.test_restore:
        logging.info(f"Performing a test restore for archive '{args.test_restore}'.")
        test_restore_borg_archive(config, args.test_restore)
        return

    # By default, if no flags, run the backup
    logging.info("Running the full Borg backup.")
    run_borg_backup(config)

if __name__ == "__main__":
    main()
