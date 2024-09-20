import yaml
import os
import argparse
import subprocess

CONFIG_PATH = "/etc/eos/borg_config.yaml"
REPOKEY_PATH = "/etc/eos/repokey"

# Default configuration values
DEFAULT_CONFIG = {
    'borg': {
        'repo': '',
        'passphrase': ''
    },
    'backup': {
        'encryption': 'repokey',  # Default encryption method added
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
            '/var',
            '/opt'
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
    """Create the YAML config file with default values and prompt for repo, passphrase, and encryption."""
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
    
    # Initialize the repository with repokey encryption
    init_repo_with_encryption(repo, passphrase)

def init_repo_with_encryption(repo, passphrase):
    """Initialize a Borg repository with repokey encryption and store the repokey."""
    print("Initializing Borg repository with repokey encryption...")
    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    try:
        # Initialize the repository with encryption
        subprocess.run(
            ['borg', 'init', '--encryption=repokey', repo],
            check=True,
            env=env
        )
        
        # Store or append the repokey
        store_repokey(repo)
    except subprocess.CalledProcessError as e:
        print(f"Error initializing Borg repository: {e}")

def store_repokey(repo):
    """Store or append the repokey in /etc/eos/repokey."""
    print(f"Storing repokey for repo: {repo}")
    
    # Simulate repokey retrieval for demo purposes
    repokey = f"repokey-for-{repo}"

    # Append to the repokey file
    with open(REPOKEY_PATH, 'a') as file:
        file.write(f"Repo: {repo}\nRepokey: {repokey}\n")
    
    print(f"Repokey stored in {REPOKEY_PATH}")

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
    """Update the YAML configuration​⬤
