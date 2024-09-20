import yaml
import os
import argparse

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Default configuration values
DEFAULT_CONFIG = {
    'borg': {
        'repo': '',
        'passphrase': ''
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
        print("Configuration file not found.")
        return None

def update_config(new_data):
    """Update the YAML configuration file with new data."""
    with open(CONFIG_PATH, 'w') as file:
        yaml.dump(new_data, file)
        print("Configuration updated.")

def print_defaults():
    """Print the default configuration."""
    print("Default configuration values:")
    print(yaml.dump(DEFAULT_CONFIG, default_flow_style=False))

def read_config():
    """Read and print the current configuration."""
    config = load_config()
    if config:
        print("Current configuration:")
        print(yaml.dump(config, default_flow_style=False))

def edit_config():
    """Edit the configuration, specifically the repo and passphrase."""
    config = load_config()
    if config:
        repo = input(f"Enter new Borg repository path (current: {config['borg']['repo']}): ") or config['borg']['repo']
        passphrase = input(f"Enter new Borg passphrase (current: {config['borg']['passphrase']}): ") or config['borg']['passphrase']
        
        config['borg']['repo'] = repo
        config['borg']['passphrase'] = passphrase
        
        update_config(config)

def main():
    parser = argparse.ArgumentParser(description="Borg YAML Configuration Wrapper")
    parser.add_argument('--create', help="Create the YAML configuration file", action='store_true')
    parser.add_argument('--read', help="Read the current configuration", action='store_true')
    parser.add_argument('--edit', help="Edit the Borg repository and passphrase", action='store_true')
    parser.add_argument('--see-defaults', help="See the default configuration values", action='store_true')
    
    args = parser.parse_args()

    if args.create:
        if not os.path.exists(CONFIG_PATH):
            create_default_config()
        else:
            print(f"Configuration file already exists at {CONFIG_PATH}")
    
    elif args.read:
        read_config()
    
    elif args.edit:
        edit_config()
    
    elif args.see_defaults:
        print_defaults()

    else:
        print("No valid flag provided. Use --help for more information.")

if __name__ == "__main__":
    main()
