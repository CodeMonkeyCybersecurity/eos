import os
import shutil
import subprocess
from datetime import datetime

INSTALL_DIR = "/usr/local/bin/eos"
EOS_CONFIGS = "/etc/eos"
EOS_LOGS = "/var/log/eos"
BACKUP_DIR = "/usr/local/bin/eos_backup"
SCRIPT_NAME = "run"
SCRIPT_PATH = os.path.join(INSTALL_DIR, SCRIPT_NAME)
SOURCE_DIR = os.path.join(os.getcwd(), "scripts")
LOG_FILE = "/var/log/eos/install.log"


def log_message(message):
    """Logs a message to the install log file."""
    # Ensure the EOS_LOGS directory exists before writing
    os.makedirs(EOS_LOGS, exist_ok=True)
    with open(LOG_FILE, 'a') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"{timestamp} - {message}\n")


def add_to_path():
    """Add the INSTALL_DIR to the PATH in the user's shell configuration."""
    shell_rc = None
    bashrc = os.path.expanduser("~/.bashrc")
    zshrc = os.path.expanduser("~/.zshrc")

    if os.path.isfile(bashrc):
        shell_rc = bashrc
    elif os.path.isfile(zshrc):
        shell_rc = zshrc
    else:
        log_message("Neither .bashrc nor .zshrc found. Exiting.")
        print(f"Neither .bashrc nor .zshrc found. Please add {INSTALL_DIR} to your PATH manually.")
        exit(1)

    with open(shell_rc, 'r+') as f:
        content = f.read()
        if INSTALL_DIR not in content:
            f.write(f'\nexport PATH="$PATH:{INSTALL_DIR}"\n')
            log_message(f"{INSTALL_DIR} added to PATH in {shell_rc}")
            print(f"{INSTALL_DIR} has been added to your PATH in {shell_rc}.")
            subprocess.run(['source', shell_rc], shell=True)
        else:
            log_message(f"{INSTALL_DIR} already in PATH.")
            print(f"{INSTALL_DIR} is already in your PATH.")


def check_dependencies():
    """Check if required commands are available."""
    commands = ["sudo", "cp", "mkdir", "chmod", "rm"]
    for cmd in commands:
        if not shutil.which(cmd):
            log_message(f"Error: {cmd} is not installed.")
            print(f"Error: {cmd} is not installed. Please install it and try again.")
            exit(1)


def backup_existing_install():
    """Backup existing installation if it exists."""
    if os.path.exists(INSTALL_DIR):
        print(f"Existing installation found. Backing up to {BACKUP_DIR}.")
        log_message(f"Backing up existing installation to {BACKUP_DIR}.")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        backup_path = os.path.join(BACKUP_DIR, datetime.now().strftime('%Y%m%d%H%M%S'))
        shutil.move(INSTALL_DIR, backup_path)


def clean_install():
    """Remove the existing installation if confirmed by the user."""
    if os.path.exists(INSTALL_DIR):
        answer = input(f"Do you want to remove the existing installation at {INSTALL_DIR}? [y/n]: ").strip().lower()
        if answer == 'y':
            log_message(f"Removing existing installation at {INSTALL_DIR}")
            shutil.rmtree(INSTALL_DIR)
        else:
            print("Installation aborted.")
            log_message("Installation aborted by user.")
            exit(0)


def install_fresh():
    """Create fresh target directories."""
    print(f"Creating target directories: {INSTALL_DIR}, {EOS_CONFIGS}, {EOS_LOGS}")
    log_message(f"Creating directories: {INSTALL_DIR}, {EOS_CONFIGS}, {EOS_LOGS}")
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(EOS_CONFIGS, exist_ok=True)
    os.makedirs(EOS_LOGS, exist_ok=True)


def move_script():
    """Move the main script to the target directory."""
    if os.path.isfile(SCRIPT_NAME):
        shutil.copy(SCRIPT_NAME, INSTALL_DIR)
        log_message(f"Moving {SCRIPT_NAME} to {INSTALL_DIR}")
    else:
        print(f"Error: Script {SCRIPT_NAME} not found in the current directory.")
        log_message(f"Error: Script {SCRIPT_NAME} not found.")
        exit(1)


def make_executable():
    """Make the script executable."""
    os.chmod(SCRIPT_PATH, 0o755)
    log_message(f"Making {SCRIPT_NAME} executable.")


def move_additional_scripts():
    """Move all additional scripts to the target directory."""
    if not os.path.isdir(SOURCE_DIR):
        log_message(f"Error: Source directory {SOURCE_DIR} does not exist.")
        print(f"Error: Source directory {SOURCE_DIR} does not exist.")
        exit(1)

    print(f"Moving scripts from {SOURCE_DIR} to {INSTALL_DIR}")
    log_message(f"Moving scripts from {SOURCE_DIR} to {INSTALL_DIR}")
    for file in os.listdir(SOURCE_DIR):
        file_path = os.path.join(SOURCE_DIR, file)
        if os.path.isfile(file_path):
            shutil.copy(file_path, INSTALL_DIR)
            os.chmod(os.path.join(INSTALL_DIR, file), 0o755)
    log_message("All scripts moved and made executable.")


def main():
    """Main installation process."""
    log_message("Starting installation process.")
    check_dependencies()
    backup_existing_install()
    clean_install()
    install_fresh()
    move_script()
    make_executable()
    move_additional_scripts()
    add_to_path()
    log_message("Installation complete.")
    print("Installation complete. Check /var/log/eos/install.log for details.")


if __name__ == "__main__":
    main()
