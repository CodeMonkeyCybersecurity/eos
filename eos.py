import os
import sys
import shutil
import subprocess
from datetime import datetime

# Default directories for installation
EOS_DIR = "/usr/local/bin/eos"
EOS_SCRIPTS_DIR = os.path.join(EOS_DIR, "scripts")
EOS_CONFIGS = "/etc/eos"
EOS_LOGS = "/var/log/eos"
BACKUP_DIR = "/usr/local/bin/eos_backup"
SCRIPT_NAME = "eos.py"
SOURCE_DIR = os.path.join(os.getcwd(), "scripts")  # Your scripts directory in the current working directory
LOG_FILE = "/var/log/eos_install.log"


def log_action(message):
    """Logs actions to a specified log file."""
    os.makedirs(EOS_LOGS, exist_ok=True)
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")


# -------- INSTALLATION FUNCTIONS -------- #
def check_dependencies():
    """Check if required commands are available."""
    commands = ["sudo", "cp", "mkdir", "chmod", "rm"]
    for cmd in commands:
        if not shutil.which(cmd):
            log_action(f"Error: {cmd} is not installed.")
            print(f"Error: {cmd} is not installed. Please install it and try again.")
            sys.exit(1)


def backup_existing_install():
    """Backup existing installation if it exists."""
    if os.path.exists(EOS_DIR):
        print(f"Existing installation found. Backing up to {BACKUP_DIR}.")
        log_action(f"Backing up existing installation to {BACKUP_DIR}.")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        backup_path = os.path.join(BACKUP_DIR, datetime.now().strftime('%Y%m%d%H%M%S'))
        shutil.move(EOS_DIR, backup_path)


def clean_install():
    """Remove the existing installation if confirmed by the user."""
    if os.path.exists(EOS_DIR):
        answer = input(f"Do you want to remove the existing installation at {EOS_DIR}? [y/n]: ").strip().lower()
        if answer == 'y':
            log_action(f"Removing existing installation at {EOS_DIR}")
            shutil.rmtree(EOS_DIR)
        else:
            print("Installation aborted.")
            log_action("Installation aborted by user.")
            sys.exit(0)


def install_fresh():
    """Create fresh target directories."""
    print(f"Creating target directories: {EOS_DIR}, {EOS_SCRIPTS_DIR}, {EOS_CONFIGS}, {EOS_LOGS}")
    log_action(f"Creating directories: {EOS_DIR}, {EOS_SCRIPTS_DIR}, {EOS_CONFIGS}, {EOS_LOGS}")
    os.makedirs(EOS_DIR, exist_ok=True)
    os.makedirs(EOS_SCRIPTS_DIR, exist_ok=True)
    os.makedirs(EOS_CONFIGS, exist_ok=True)
    os.makedirs(EOS_LOGS, exist_ok=True)


def move_eos_script():
    """Move the eos.py script to the target directory."""
    eos_script_path = os.path.join(os.getcwd(), SCRIPT_NAME)  # Assume eos.py is in the current directory
    if not os.path.isfile(eos_script_path):
        print(f"Error: '{SCRIPT_NAME}' not found in the current directory.")
        sys.exit(1)

    print(f"Moving '{SCRIPT_NAME}' to {EOS_DIR}")
    log_action(f"Moving '{SCRIPT_NAME}' to {EOS_DIR}")
    shutil.copy(eos_script_path, EOS_DIR)
    os.chmod(os.path.join(EOS_DIR, SCRIPT_NAME), 0o755)
    log_action(f"'{SCRIPT_NAME}' moved and made executable.")


def move_other_scripts():
    """Move the other scripts to the target scripts directory."""
    if not os.path.isdir(SOURCE_DIR):
        log_action(f"Error: Source directory {SOURCE_DIR} does not exist.")
        print(f"Error: Source directory {SOURCE_DIR} does not exist.")
        sys.exit(1)

    print(f"Moving scripts from {SOURCE_DIR} to {EOS_SCRIPTS_DIR}")
    log_action(f"Moving scripts from {SOURCE_DIR} to {EOS_SCRIPTS_DIR}")
    for file in os.listdir(SOURCE_DIR):
        file_path = os.path.join(SOURCE_DIR, file)
        if os.path.isfile(file_path):
            shutil.copy(file_path, EOS_SCRIPTS_DIR)
            os.chmod(os.path.join(EOS_SCRIPTS_DIR, file), 0o755)
    log_action("All scripts moved and made executable.")


# -------- MAIN FUNCTION -------- #
def main():
    # Check if the script is running in "install" mode
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        log_action("Starting installation process.")
        check_dependencies()
        backup_existing_install()
        clean_install()
        install_fresh()
        move_eos_script()  # Move eos.py to /usr/local/bin/eos
        move_other_scripts()  # Move other scripts to /usr/local/bin/eos/scripts
        log_action("Installation complete.")
        print("Installation complete. Check /var/log/eos_install.log for details.")
        sys.exit(0)

    # If not "install" mode, show help
    print("Error: Invalid mode. Use 'install' to run the installation.")
    sys.exit(1)


if __name__ == "__main__":
    main()
