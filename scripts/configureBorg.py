import yaml
import os
import argparse

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Default configuration values (for reference)
DEFAULT_CONFIG = {
    'borg': {
        'repo': '',
        'passphrase': '',
        'encryption': 'repokey'  # Default encryption method added
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
        print(f"Configuration file not found at {CONFIG_PATH}.")
        return None

def update_config(config):
    """Update the YAML configuration file with new data."""
    with open(CONFIG_PATH, 'w') as file:
        yaml.dump(config, file)
        print("Configuration updated.")

def edit_variable(config, variable, value):
    """Edit a specific variable in the configuration."""
    if variable == 'repo':
        config['borg']['repo'] = value
    elif variable == 'passphrase':
        config['borg']['passphrase'] = value
    elif variable == 'encryption':
        config['borg']['encryption'] = value or 'repokey'  # Set default encryption to 'repokey' if not provided
    elif variable == 'filter':
        config['backup']['filter'] = value
    elif variable == 'compression':
        config['backup']['compression'] = value
    else:
        print(f"Unsupported variable: {variable}")
        return False
    return True

def prompt_for_variable(config):
    """Prompt the user for which variable to edit."""
    print("Which variable would you like to edit?")
    print("1: repo")
    print("2: passphrase")
    print("3: encryption")
    print("4: filter")
    print("5: compression")
    choice = input("Enter the number of the variable to edit: ")

    variables = {
        '1': ('repo', config['borg']['repo']),
        '2': ('passphrase', config['borg']['passphrase']),
        '3': ('encryption', config['borg'].get('encryption', 'repokey')),  # Default to 'repokey'
        '4': ('filter', config['backup']['filter']),
        '5': ('compression', config['backup']['compression'])
    }

    variable, default_value = variables.get(choice, (None, None))
    if variable:
        value = input(f"Enter new value for {variable} (default: {default_value}): ") or default_value
        return variable, value
    return None, None

def main():
    parser = argparse.ArgumentParser(description="Borg YAML Configuration Editor")
    parser.add_argument('--edit', help="Edit the YAML configuration", action='store_true')
    parser.add_argument('--repo', help="Edit the repository URL", type=str)
    parser.add_argument('--passphrase', help="Edit the passphrase", type=str)
    parser.add_argument('--encryption', help="Edit the encryption method", type=str)
    parser.add_argument('--filter', help="Edit the filter for backups", type=str)
    parser.add_argument('--compression', help="Edit the compression method", type=str)

    args = parser.parse_args()

    # Load the configuration
    config = load_config()
    if not config:
        return  # Exit if the configuration file is not found

    # If no specific flag is provided, prompt the user for input
    if args.edit and not any([args.repo, args.passphrase, args.encryption, args.filter, args.compression]):
        variable, value = prompt_for_variable(config)
        if variable:
            if edit_variable(config, variable, value):
                update_config(config)
        else:
            print("Invalid choice. Exiting.")
        return

    # Edit specific values if flags are passed
    if args.repo:
        edit_variable(config, 'repo', args.repo)
    if args.passphrase:
        edit_variable(config, 'passphrase', args.passphrase)
    if args.encryption:
        edit_variable(config, 'encryption', args.encryption)
    if args.filter:
        edit_variable(config, 'filter', args.filter)
    if args.compression:
        edit_variable(config, 'compression', args.compression)

    # Save the configuration if any variable was edited
    if any([args.repo, args.passphrase, args.encryption, args.filter, args.compression]):
        update_config(config)

if __name__ == "__main__":
    main()
