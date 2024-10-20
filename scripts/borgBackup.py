import yaml
import os
import subprocess
import logging
from datetime import datetime
import socket  # Used to get the hostname

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Set up logging to output to both a file and the console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/eos.log"),  # Change this to the desired log file path
        logging.StreamHandler()  # This will continue printing logs to the console
    ]
)

# Function to run Borg backup
def run_borg_backup(config, dryrun=False):
    """Run the Borg backup using the configuration values."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']
    paths = config['backup']['paths_to_backup']
    compression = config['backup'].get('compression', 'zstd')  # Default to 'zstd' if not specified

    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    hostname = socket.gethostname()  # Get the actual hostname of the machine
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    archive_name = f"{repo}::{hostname}-{timestamp}"

    borg_create_cmd = ['borg', 'create', archive_name] + paths + [
        '--verbose',
        '--compression', compression,
        '--list',
        '--stats',
        '--show-rc',
        '--exclude-caches'
    ]

    # Add any exclude patterns from config
    for pattern in config['backup'].get('exclude_patterns', []):
        borg_create_cmd += ['--exclude', pattern]

    if dryrun:
        borg_create_cmd.append('--dry-run')

    try:
        result = subprocess.run(borg_create_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error(f"Borg backup failed: {e.stderr}")

# Prompt user to go to repository menu
def prompt_for_repository_menu():
    """Prompt the user if they want to go to the repository options menu."""
    while True:
        user_input = input("The repository is invalid. Would you like to go to the repository options to fix it? (y/N): ").lower()
        if user_input == 'y':
            repository_options_menu()
            break
        elif user_input == 'n' or user_input == '':
            break
        else:
            print("Invalid input. Please type 'y' for Yes or 'n' for No.")

def repository_options_menu():
    """Handle the repository options menu."""
    while True:
        print("\nRepository Options:")
        print("(1) View current repository path")
        print("(2) Change repository path")
        print("(3) Check repository health")
        print("(4) Return to main menu")
        print("(E) Exit")

        choice = input("Select an option: ").upper()

        if choice == '1':
            config = load_config()
            if config:
                print(f"Current repository: {config['borg']['repo']}")
        elif choice == '2':
            config = load_config()
            if config:
                config['borg']['repo'] = input("Enter the new repository path (e.g., user@backup-server:/path/to/repo): ")
                save_config(config)
        elif choice == '3':
            config = load_config()
            if config:
                check_repo(config)
        elif choice == '4':
            break
        elif choice == 'E':
            exit_program()
        else:
            print("Invalid option. Please try again.")

# Check the repository
def check_repo(config):
    """Check repository health with 'borg check'."""
    repo = config['borg']['repo']
    passphrase = config['borg']['passphrase']

    env = os.environ.copy()
    env['BORG_PASSPHRASE'] = passphrase

    try:
        result = subprocess.run(['borg', 'check', repo], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        logging.info(result.stdout)
        print("Repository check passed.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Repository check failed: {e.stderr}")

# Clear the screen
def clear_screen():
    """Clear the terminal screen."""
    os.system('clear')

# Load the YAML configuration
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

# Save the YAML configuration
def save_config(config):
    """Save the modified YAML config file."""
    try:
        with open(CONFIG_PATH, 'w') as file:
            yaml.safe_dump(config, file)
        logging.info(f"Configuration updated and saved to {CONFIG_PATH}.")
    except OSError as e:
        logging.error(f"Failed to write the configuration file: {e}")

# Edit YAML menu
def edit_yaml_menu(config):
    """Display YAML editing options."""
    while True:
        print("\nEditting existing YAML file. What would you like to edit?")
        print("(0) Compression method (eg. lz4, zstd. Default is zstd)")
        print("(1) Enter the encryption type (e.g., repokey, none)")
        print("(2) Borg repository path (e.g., user@backup-server:/path/to/repo. You must make sure this exists and is available prior to running a backup)")
        print("(3) Enter the directories to back up (comma-separated, default is: /etc,/var,/home,/mnt,/root,/opt)")
        print("(4) Enter exclude patterns (comma-separated, default is: home/*/.cache/*,var/tmp/*)")
        print("(5) Prune settings (comma-separated in format d,w,m,y. Default is 30,0,0,0)")
        print("(6) Edit with nano")
        print("(7) Return to main Menu")
        print("(E) (E)xit")
        
        choice = input("Select an option: ").upper()

        if choice == '0':
            config['backup']['compression'] = input("Enter the compression method (e.g., lz4, zstd, default is zstd): ")
            save_config(config)
        elif choice == '1':
            config['borg']['encryption'] = input("Enter the encryption type (e.g., repokey, none): ")
            save_config(config)
        elif choice == '2':
            config['borg']['repo'] = input("Enter the Borg repository path (e.g., user@backup-server:/path/to/repo): ")
            save_config(config)
        elif choice == '3':
            config['backup']['paths_to_backup'] = input("Enter the directories to back up (comma-separated, default is /etc,/var,/home,/mnt,/root,/opt): ").split(',')
            save_config(config)
        elif choice == '4':
            config['backup']['exclude_patterns'] = input("Enter exclude patterns (comma-separated, default is home/*/.cache/*,var/tmp/*): ").split(',')
            save_config(config)
        elif choice == '5':
            prune_settings = input("Enter prune settings (comma-separated in format d,w,m,y. Default is 30,0,0,0): ").split(',')
            config['backup']['prune'] = {
                'daily': prune_settings[0],
                'weekly': prune_settings[1],
                'monthly': prune_settings[2],
                'yearly': prune_settings[3]
            }
            save_config(config)
        elif choice == '6':
            os.system(f"nano {CONFIG_PATH}")  # Open the YAML file with nano for manual editing
        elif choice == '7':
            break  # Return to the main menu
        elif choice == 'E':
            exit_program()
        else:
            print("Invalid option. Please try again.")

# Display main menu
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
    print("(N) Run backup (N)ow")  # New option to run backup immediately
    print("(E) (E)xit")
    logging.info("Displaying main menu")

# Display submenu
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
    logging.info("Displaying main submenu")

# Handle submenu option
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
        edit_yaml_menu(config)  # Go to YAML edit menu
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

# Exit the script
def exit_program():
    """Exit the script."""
    print("Exiting the program. Goodbye!")
    exit()

# Main program loop
def main():
    while True:
        clear_screen()
        display_menu()
        choice = input("Select an option: ").upper()

        if choice == 'M':
            continue  # Show the menu again
        elif choice == 'H':
            print("Help: This is a Borg Backup tool for managing backups and repositories.")
        elif choice == 'N':  # Run backup immediately
            config = load_config()  # Ensure config is loaded
            if config:
                logging.info("Running backup immediately with current configuration.")
                run_borg_backup(config)  # Ensure this runs
            else:
                logging.error("No valid configuration found. Unable to run backup.")
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
