import yaml
import os
import subprocess
import logging
from datetime import datetime
import socket  # Used to get the hostname

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def clear_screen():
    """Clear the terminal screen."""
    os.system('clear')

def create_yaml_config():
    """Create the YAML config file at /etc/eos/borg_config.yaml."""
    config = {
        'borg': {
            'repo': input("Enter the Borg repository path (e.g., user@backup-server:/path/to/repo): "),
            'passphrase': input("Enter the Borg passphrase: "),
            'encryption': input("Enter the encryption type (e.g., repokey, none): ")
        },
        'backup': {
            'paths_to_backup': input("Enter the directories to back up (comma-separated): ").split(','),
            'exclude_patterns': input("Enter exclude patterns (comma-separated): ").split(','),
            'compression': input("Enter the compression method (e.g., lz4, zstd): ")
        }
    }

    # Save to YAML
    try:
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, 'w') as file:
            yaml.safe_dump(config, file)
        logging.info(f"Configuration saved to {CONFIG_PATH}.")
    except OSError as e:
        logging.error(f"Failed to write the configuration file: {e}")

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
        logging.error(f"Configuration file not found.")
        return None

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

    if dryrun:
        borg_create_cmd.append('--dry-run')

    try:
        result = subprocess.run(borg_create_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Borg backup failed: {e.stderr}")

def display_menu():
    """Display the main menu."""
    print("Welcome to Code Monkey Cybersecurity's borgBackup.py.")
    print("What would you like to do? Type the letter of the option you want and press enter:")
    print("(M) Show this (M)enu")
    print("(H) Show (H)elp")
    print("(Y) Go to (Y)AML options")
    print("(O) Go to repository (O)ptions")
    print("(B) Go to (B)ackup options")
    print("(R) Go to (R)estore options")
    print("(D) Go to (D)ebugging options")
    print("(A) Go to (A)rchive options")
    print("(E) (E)xit")
    
def display_submenu():
    """Display the submenu for the selected section."""
    print("\n(0) Run backup with current configuration")
    print("(1) Print out current configuration")
    print("(2) Create new configuration")
    print("(3) Edit existing configuration")
    print("(4) Perform a dry run with current configuration")
    print("(5) Delete current configuration")
    print("(6) Replace current configuration")
    print("(7) Return to main Menu")
    print("(E) (E)xit")

def handle_submenu_option(option):
    """Handle user options from the submenu."""
    config = load_config()
    
    if option == '0' and config:
        run_borg_backup(config)
    elif option == '1':
        print("Current configuration:")
        print(config)
    elif option == '2':
        create_yaml_config()
    elif option == '3' and config:
        print("Editing configuration (manual changes may be required).")
        create_yaml_config()  # Simplified editing process for now
    elif option == '4' and config:
        run_borg_backup(config, dryrun=True)
    elif option == '5' and config:
        try:
            os.remove(CONFIG_PATH)
            print("Configuration deleted.")
        except OSError as e:
            print(f"Error deleting configuration: {e}")
    elif option == '6':
        create_yaml_config()
    elif option == '7':
        return
    elif option == 'E':
        exit_program()
    else:
        print("Invalid option or no configuration available. Please choose a valid option.")

def exit_program():
    """Exit the script."""
    print("Exiting the program. Goodbye!")
    exit()

def main():
    while True:
        clear_screen()
        display_menu()
        choice = input("Select an option: ").upper()

        if choice == 'M':
            continue  # Show the menu again
        elif choice == 'H':
            print("Help: This is a Borg Backup tool for managing backups and repositories.")
        elif choice in ['Y', 'O', 'B', 'R', 'D', 'A']:
            while True:
                display_submenu()
                submenu_choice = input("Select an option: ").upper()
                if submenu_choice == '7':
                    break  # Return to the main menu
                handle_submenu_option(submenu_choice)
        elif choice == 'E':
            exit_program()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
