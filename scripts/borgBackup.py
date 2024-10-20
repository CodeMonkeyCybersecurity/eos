import yaml
import os
import subprocess
import logging
from datetime import datetime
import socket  # Used to get the hostname

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        if "not a valid repository" in e.stderr.lower():
            prompt_for_repository_menu()

# Add prompt for repository menu in case of issues
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

# Function to display and handle repository options
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

# Add function to handle the new "Run backup now" option
def run_backup_now():
    """Run backup immediately with the current configuration."""
    config = load_config()
    if config:
        run_borg_backup(config)
    else:
        print("No configuration found. Please create one first.")

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

def main():
    while True:
        clear_screen()
        display_menu()
        choice = input("Select an option: ").upper()

        if choice == 'M':
            continue  # Show the menu again
        elif choice == 'H':
            print("Help: This is a Borg Backup tool for managing backups and repositories.")
        elif choice == 'Y':
            display_submenu()
        elif choice == 'O':
            repository_options_menu()
        elif choice == 'B':
            display_submenu()
        elif choice == 'R':
            display_submenu()
        elif choice == 'D':
            display_submenu()
        elif choice == 'A':
            display_submenu()
        elif choice == 'N':  # Run backup now option
            run_backup_now()  # Run the backup immediately with the current configuration
        elif choice == 'E':
            exit_program()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
