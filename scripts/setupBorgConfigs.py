import yaml
import os

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Default configuration values
DEFAULT_CONFIG = {
    'borg': {
        'repo': '',  # To be provided by the user
        'passphrase': ''  # To be provided by the user
    },
    'backup': {
        'verbose': True,
        'filter': 'AME',
        'list': True,
        'stats': True,
        'show_rc': True,
        'compression': 'lz4',
        'exclude_caches': True,
        'exclude_patterns': [
            'home/*/.cache/*',
            'var/tmp/*'
        ],
        'paths_to_backup': [
            '/etc',
            '/home',
            '/root',
            '/var'
        ]
    },
    'prune': {
        'list': True,
        'glob_archives': '{hostname}-*',
        'show_rc': True,
        'keep': {
            'daily': 7,
            'weekly': 4,
            'monthly': 6
        }
    },
    'compact': True
}

def create_default_config():
    """Create the YAML config file with default values and prompt for repo and passphrase."""
    print("Creating a new configuration file.")
    
    # Prompt user for repo and passphrase
    repo = input("Enter the Borg repository path (e.g., ssh://username@host:port/path): ")
    passphrase = input("Enter the Borg passphrase: ")
    
    # Update the default configuration with user-provided values
    DEFAULT_CONFIG['borg']['repo'] = repo
    DEFAULT_CONFIG['borg']['passphrase'] = passphrase
    
    # Save the configuration to the YAML file
    with open(CONFIG_PATH, 'w') as file:
        yaml.dump(DEFAULT_CONFIG, file)
        print(f"Configuration created at {CONFIG_PATH}")

def load_config():
    """Load configuration from YAML file."""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as file:
            try:
                config = yaml.safe_load(file)
                return config
            except yaml.YAMLError as e:
                print(f"Error loading configuration file: {e}")
                return None
    else:
        print("Configuration file not found. Creating one now...")
        create_default_config()
        return load_config()  # Reload after creation

def update_config(new_data):
    """Update the YAML configuration file with new data."""
    with open(CONFIG_PATH, 'w') as file:
        yaml.dump(new_data, file)
        print("Configuration updated.")

# Example of accessing configuration values
config = load_config()
if config:
    print(f"Borg Repository: {config['borg']['repo']}")
    print(f"Backup Paths: {config['backup']['paths_to_backup']}")

# Example of updating the configuration
if config:
    # Modify the repo and save it back to the config file
    config['borg']['repo'] = 'ssh://newuser@newhost.com:2222/~/newbackup/main'
    update_config(config)
