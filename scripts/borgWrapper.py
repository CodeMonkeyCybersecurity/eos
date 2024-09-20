import yaml
import os
import subprocess
import logging

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config():
    """Load configuration from YAML file."""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as file:
            try:
                config = yaml.safe_load(file)
                return config
            except yaml.YAMLError as e:
                logging.error(f"Error loading configuration file: {e}")
                return None
    else:
        logging.error(f"Configuration file not found. Please run 'sudo python3 configureBorg.py --create'")
        return None

def check_config_values(config):
    """Check if all required configuration values are set correctly."""
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
    return True

def run_borg_backup(config):
    """Run the Borg backup using the configuration values."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']
    paths = config['backup']['paths_to_backup']
    encryption = config['backup']['encryption']

    # Set the environment variable for passphrase
    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    # Build the borg create command
    borg_create_cmd = [
        'borg', 'create', f'{repo}::{{hostname}}-{{now}}'
    ] + paths + [
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

    try:
        # Run the borg create command
        result = subprocess.run(
            borg_create_cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True
        )
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Borg backup failed: {e.stderr}")

def main():
    # Load the configuration
    config = load_config()
    if not config:
        return  # Exit if config is not loaded

    # Check if all required configuration values are set
    if check_config_values(config):
        logging.info("All configuration values are correct. Proceeding with the backup.")
        run_borg_backup(config)
    else:
        logging.error("One or more configuration values are missing or incorrect. Backup aborted.")

if __name__ == "__main__":
    main()
