import yaml
import os
import subprocess
import logging
from datetime import datetime
import socket  # Used to get the hostname

CONFIG_PATH = "/etc/eos/borg_config.yaml"

# Set up logging to output to both a file and the console
file_handler = logging.FileHandler("/var/log/eos.log")
file_handler.setLevel(logging.DEBUG)  # Log all levels to the log file

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)  # Only log errors or higher to the console

logging.basicConfig(
    level=logging.DEBUG,  # Overall log level
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[file_handler, console_handler]
)

# Error handling for setting TMPDIR environment variable
try:
    tmp_dir = "/home/henry/tmp"
    
    # Check if /home/henry/tmp exists
    if os.path.exists(tmp_dir):
        # Run df -h to check disk space
        result = subprocess.run(['df', '-h', tmp_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            output = result.stdout
            logging.info(f"Disk space check for {tmp_dir}:\n{output}")
            print(f"Disk space check for {tmp_dir}:\n{output}")
            
            # Set TMPDIR if the directory exists and the command executed successfully
            os.environ["TMPDIR"] = tmp_dir
            logging.info(f"TMPDIR set to {tmp_dir}")
        else:
            logging.error(f"Error checking disk space: {result.stderr}")
            print(f"Error: Disk space check failed. {result.stderr}")
    else:
        raise FileNotFoundError(f"Temporary directory {tmp_dir} does not exist")
    
except Exception as e:
    logging.error(f"Failed to set TMPDIR: {e}")
    print(f"Error: Could not set TMPDIR. {e}")

# Error handling for setting the BORG_RSH environment variable
try:
    ssh_key_path = os.path.expanduser("~/.ssh/id_ed25519")
    if os.path.exists(ssh_key_path):
        os.environ["BORG_RSH"] = f"ssh -i {ssh_key_path}"
        logging.info(f"BORG_RSH set to use SSH key: {ssh_key_path}")
    else:
        raise FileNotFoundError(f"SSH key not found at {ssh_key_path}")
except Exception as e:
    logging.error(f"Failed to set BORG_RSH: {e}")
    print(f"Error: Could not set BORG_RSH. {e}")

def run_borg_backup(config, dryrun=False):
    """Run the Borg backup using the configuration values."""
    try:
        # Start status update
        print("Starting Borg backup...")
        logging.info("Starting Borg backup.")

        # Extract relevant config details
        repo = config['borg']['repo']
        passphrase = config['borg']['passphrase']
        paths = config['backup']['paths_to_backup']
        compression = config['backup'].get('compression', 'zstd')  # Default to 'zstd' if not specified

        # Set up the environment for the passphrase
        env = os.environ.copy()
        env['BORG_PASSPHRASE'] = passphrase

        # Generate an archive name using the hostname and timestamp
        hostname = socket.gethostname()  # Get the actual hostname of the machine
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        archive_name = f"{repo}::{hostname}-{timestamp}"

        # Build the Borg create command
        borg_create_cmd = ['borg', 'create', archive_name] + paths + [
            '--verbose',
            '--compression', compression,
            '--list',
            '--stats',
            '--show-rc',
            '--exclude-caches'
        ]

        # Add exclude patterns from config
        for pattern in config['backup'].get('exclude_patterns', []):
            borg_create_cmd += ['--exclude', pattern]

        # Add dry-run flag if specified
        if dryrun:
            borg_create_cmd.append('--dry-run')

        # Status update before running the command
        print("Running Borg backup command...")
        logging.info("Running Borg backup command.")
        
        # Run the Borg create command
        result = subprocess.run(borg_create_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        
        # Success update
        logging.info(result.stdout)  # Log the output of the command
        print(f"Borg backup completed successfully!\n{result.stdout}")  # Print the result to console

    except subprocess.CalledProcessError as e:
        # Failure update
        logging.error(f"Borg backup failed: {e.stderr}")
        print(f"Error: Borg backup failed. {e.stderr}")
        prompt_for_repository_menu()  # Prompt for repository fix if backup fails

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


# Modify the repository_options_menu function to show success/failure
def repository_options_menu():
    """Handle the repository options menu."""
    while True:
        print("\nRepository Options:")
        print("(1) View current repository path")
        print("(2) Change repository path")
        print("(3) Check repository health")
        print("(4) Create a new repository")  # Add option to create new repository
        print("(M) Return to main menu")
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
                print("Repository path updated successfully.")  # Indicate success
        elif choice == '3':
            config = load_config()
            if config:
                success = check_repo(config)
                if success:
                    print("Repository health check completed successfully.")  # Indicate success
                else:
                    print("Repository health check failed.")  # Indicate failure
        elif choice == '4':  # Create a new repository
            config = load_config()
            if config:
                success = create_borg_repository(config)
                if success:
                    print("New repository created successfully.")  # Indicate success
                else:
                    print("Failed to create the repository.")  # Indicate failure
        elif choice == 'M':
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
        print(f"Repository check passed for {repo}.")  # Success message
        return True  # Indicate success
    except subprocess.CalledProcessError as e:
        logging.error(f"Repository check failed: {e.stderr}")
        print(f"Error: Repository check failed for {repo}. {e.stderr}")  # Failure message
        return False  # Indicate failure

# Create a repository
def create_borg_repository(config):
    """Initialize a new Borg repository."""
    try:
        repo = config['borg']['repo']
        passphrase = config['borg']['passphrase']
        
        # Set up environment for Borg init
        env = os.environ.copy()
        env['BORG_PASSPHRASE'] = passphrase
        
        # Initialize the repository with encryption if set
        encryption_type = config['borg'].get('encryption', 'repokey')

        # Run Borg init command
        borg_init_cmd = ['borg', 'init', '--encryption', encryption_type, repo]
        result = subprocess.run(borg_init_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)

        logging.info(f"Repository {repo} created successfully.")
        print(f"Repository {repo} created successfully.")  # Success message
        return True  # Indicate success
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to create Borg repository: {e.stderr}")
        print(f"Error: Failed to create repository {repo}. {e.stderr}")  # Failure message
        return False  # Indicate failure

# Clear the screen
def clear_screen():
    """Clear the terminal screen."""
    os.system('clear')

# Load the YAML configuration
def create_yaml_config():
    """Create the YAML config file at /etc/eos/borg_config.yaml with default values."""
    # Default values for the configuration
    default_repo = "henry@ubuntu-backups:/mnt/cybermonkey"
    default_passphrase = "Linseed7)Twine33Phoney57Barracuda4)Province0"
    default_encryption = "repokey"
    default_paths_to_backup = "/var,/etc,/home,/root,/opt,/mnt"
    default_exclude_patterns = "home/*/.cache/*,var/tmp/*"
    default_compression = "zstd"

    # Prompt the user for inputs, with default values suggested
    config = {
        'borg': {
            'repo': input(f"Enter the Borg repository path (default: {default_repo}): ") or default_repo,
            'passphrase': input(f"Enter the Borg passphrase (default: {default_passphrase}): ") or default_passphrase,
            'encryption': input(f"Enter the encryption type (e.g., repokey, none, default: {default_encryption}): ") or default_encryption
        },
        'backup': {
            'paths_to_backup': input(f"Enter the directories to back up (comma-separated, default: {default_paths_to_backup}): ") or default_paths_to_backup,
            'exclude_patterns': input(f"Enter exclude patterns (comma-separated, default: {default_exclude_patterns}): ") or default_exclude_patterns,
            'compression': input(f"Enter the compression method (e.g., lz4, zstd, default: {default_compression}): ") or default_compression
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
        print("\nEditing existing YAML file. What would you like to edit?")
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
            config['backup']['paths_to_backup'] = (input(f"Enter the directories to back up (comma-separated, default: /etc,/var,/home,/mnt,/root,/opt): ") or "/etc,/var,/home,/mnt,/root,/opt").split(',')
            config['backup']['exclude_patterns'] = (input(f"Enter exclude patterns (comma-separated, default: home/*/.cache/*,var/tmp/*): ") or "home/*/.cache/*,var/tmp/*").split(',')
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

# Set up logging to output to both a file and the console
file_handler = logging.FileHandler("/var/log/eos.log")
file_handler.setLevel(logging.DEBUG)  # Log all levels to the log file

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.ERROR)  # Only log errors or higher to the console

logging.basicConfig(
    level=logging.DEBUG,  # Overall log level
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[file_handler, console_handler]
)

def add_borg_to_crontab(config):
    """Add Borg backup to crontab with error handling."""
    try:
        # Prompt user for the backup schedule
        print("Enter the time for the Borg backup (24-hour format):")
        
        # Input validation for minute
        while True:
            minute = input("Minute (0-59): ")
            if minute.isdigit() and 0 <= int(minute) <= 59:
                break
            print("Invalid input. Please enter a number between 0 and 59.")
        
        # Input validation for hour
        while True:
            hour = input("Hour (0-23): ")
            if hour.isdigit() and 0 <= int(hour) <= 23:
                break
            print("Invalid input. Please enter a number between 0 and 23.")
        
        # Input validation for day of month
        while True:
            day_of_month = input("Day of month (1-31, * for every day): ")
            if day_of_month.isdigit() and 1 <= int(day_of_month) <= 31 or day_of_month == "*":
                break
            print("Invalid input. Please enter a number between 1 and 31 or * for every day.")
        
        # Input validation for month
        while True:
            month = input("Month (1-12, * for every month): ")
            if month.isdigit() and 1 <= int(month) <= 12 or month == "*":
                break
            print("Invalid input. Please enter a number between 1 and 12 or * for every month.")
        
        # Input validation for day of the week
        while True:
            day_of_week = input("Day of week (0-6, Sunday is 0 or 7, * for every day): ")
            if day_of_week.isdigit() and 0 <= int(day_of_week) <= 7 or day_of_week == "*":
                break
            print("Invalid input. Please enter a number between 0 and 7 or * for every day.")

        # Ensure that user has entered values correctly
        cron_time = f"{minute} {hour} {day_of_month} {month} {day_of_week}"

        # Command to run Borg backup using the current configuration
        borg_backup_command = (
            f"borg create {config['borg']['repo']}::{socket.gethostname()}-{datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} "
            f"{' '.join(config['backup']['paths_to_backup'])} "
            f"--compression {config['backup'].get('compression', 'zstd')} "
            f"--exclude-caches"
        )

        # Construct the crontab entry with logging
        cron_entry = f"{cron_time} {borg_backup_command} >> /var/log/eos_borg_backup.log 2>&1"

        # Check if the crontab entry already exists
        try:
            result = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                current_crontab = result.stdout
            else:
                print("No crontab for this user. Starting fresh.")
                current_crontab = ""
        except subprocess.CalledProcessError as e:
            print(f"Error: Could not retrieve current crontab. {e.stderr}")
            logging.error(f"Error retrieving current crontab: {e.stderr}")
            return

        # Append the new cron entry if not already present
        if cron_entry not in current_crontab:
            new_crontab = current_crontab + f"\n{cron_entry}\n"
            try:
                # Update the crontab
                process = subprocess.run(['crontab', '-'], input=new_crontab, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if process.returncode == 0:
                    print("Borg backup schedule added to crontab successfully.")
                    logging.info(f"Borg backup schedule added to crontab: {cron_entry}")
                else:
                    print(f"Error: Failed to update crontab. {process.stderr}")
                    logging.error(f"Error updating crontab: {process.stderr}")
            except subprocess.CalledProcessError as e:
                print(f"Error: Could not update crontab. {e.stderr}")
                logging.error(f"Failed to update crontab: {e.stderr}")
        else:
            print("This backup configuration already exists in crontab.")
            logging.info("Crontab entry already exists.")
    
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Error adding to crontab: {e}")

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
    print("(N) Run backup (N)ow")
    print("(C) Add backup to crontab")
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
    elif option == 'M':
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

#main function
def main():
    while True:
        clear_screen()
        display_menu()
        choice = input("Select an option: ").upper()

        if choice == 'C':
            config = load_config()
            if config:
                add_borg_to_crontab(config)
            else:
                print("Error: No valid configuration found.")
        elif choice == 'M':
            print("Showing the main menu...")
            logging.info("Showing the main menu.")
            continue  # Show the menu again
        elif choice == 'H':
            print("Help: This is a Borg Backup tool for managing backups and repositories.")
        elif choice == 'N':  # Run backup immediately
            print("Validating configuration for backup...")
            config = load_config()  # Ensure config is loaded
            if config:
                logging.info("Configuration validated successfully.")
                print("Running backup now...")
                run_borg_backup(config)  # Run the backup
            else:
                logging.error("No valid configuration found. Unable to run backup.")
                print("Error: No valid configuration found.")
        elif choice == 'O':  # Repository options menu
            print("Opening repository options menu...")
            repository_options_menu()  # Correctly call repository options menu
        elif choice in ['Y', 'B', 'R', 'D', 'A']:
            while True:
                display_submenu()
                submenu_choice = input("Select an option: ").upper()
                if submenu_choice == 'M':
                    break  # Return to the main menu
                else:
                    handle_submenu_option(submenu_choice)
        elif choice == 'E':
            print("Exiting program...")
            exit_program()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
