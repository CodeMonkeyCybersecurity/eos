import yaml
import os
import subprocess
import argparse
import logging
from datetime import datetime
import socket  # Used to get the hostname

CONFIG_PATH = "/etc/eos/borgBackupConfig.yaml"

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    """Load configuration from YAML file."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as file:
                config = yaml.safe_load(file)
                if config:
                    logging.info("Configuration loaded successfully.")
                    return config
                else:
                    logging.error("Configuration file is empty or invalid.")
                    return None
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
        'borg.encryption': config.get('borg', {}).get('encryption'),
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

    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    hostname = socket.gethostname()  # Get the actual hostname of the machine
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    archive_name = f"{repo}::{hostname}-{timestamp}"

    borg_create_cmd = ['borg', 'create', archive_name] + paths + [
        '--verbose',
        '--filter', config['backup']['filter'],
        '--list',
        '--stats',
        '--show-rc',
        '--compression', config['backup']['compression'],
        '--exclude-caches'
    ]

    for pattern in config['backup'].get('exclude_patterns', []):
        borg_create_cmd += ['--exclude', pattern]

    if dryrun:
        borg_create_cmd.append('--dry-run')

    try:
        result = subprocess.run(borg_create_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Borg backup failed: {e.stderr}")
        return

def list_borg_archives(config):
    """List all archives in the Borg repository."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']

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

    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    borg_restore_cmd = ['borg', 'extract', f'{repo}::{archive_name}', '--target', target_dir]

    try:
        result = subprocess.run(borg_restore_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(f"Restored archive '{archive_name}' to '{target_dir}'")
    except subprocess.CalledProcessError as e:
        logging.error(f"Restoring archive failed: {e.stderr}")

def test_restore_borg_archive(config, archive_name):
    """Perform a test restore without actually extracting the files."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']

    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    borg_test_restore_cmd = ['borg', 'extract', '--dry-run', f'{repo}::{archive_name}']

    try:
        result = subprocess.run(borg_test_restore_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(f"Test restore of archive '{archive_name}' succeeded.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Test restore failed: {e.stderr}")

def main():
    parser = argparse.ArgumentParser(description="Borg Backup Wrapper", add_help=True)
    parser.add_argument('--check-yaml', help="Check the YAML configuration", action='store_true')
    parser.add_argument('--check-repo', help="Check the Borg repository", action='store_true')
    parser.add_argument('--dryrun', help="Run a dry run of the backup", action='store_true')
    parser.add_argument('--backup', help="Run a full backup", action='store_true')
    parser.add_argument('--list', help="List all archives in the repository", action='store_true')
    parser.add_argument('--restore', help="Restore a specific archive", type=str)
    parser.add_argument('--test-restore', help="Test restore a specific archive", type=str)
    parser.add_argument('--target-dir', help="Specify the target directory for the restore", type=str)

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        return

    config = load_config()
    if not config:
        return  # Exit if the config file is not found

    if args.check_yaml:
        if check_yaml(config):
            logging.info("YAML configuration is valid.")
        else:
            logging.error("YAML configuration has issues.")
        return

    if args.check_repo:
        check_repo(config)
        return

    if args.dryrun:
        run_borg_backup(config, dryrun=True)
        return

    if args.backup:
        run_borg_backup(config)
        return

    if args.list:
        list_borg_archives(config)
        return

    if args.restore:
        if not args.target_dir:
            logging.error("Target directory must be specified for restoration.")
        else:
            restore_borg_archive(config, args.restore, args.target_dir)
        return

    if args.test_restore:
        test_restore_borg_archive(config, args.test_restore)
        return

if __name__ == "__main__":
    main()
