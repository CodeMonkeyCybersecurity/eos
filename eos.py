import os
import sys
import shutil
import subprocess
from datetime import datetime

# Default script directories and files
INSTALL_DIR = "/usr/local/bin/eos"
EOS_CONFIGS = "/etc/eos"
EOS_LOGS = "/var/log/eos"
BACKUP_DIR = "/usr/local/bin/eos_backup"
SCRIPT_NAME = "eos"
SOURCE_DIR = os.path.join(os.getcwd(), "scripts")
LOG_FILE = "/var/log/run_script.log"


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
    if os.path.exists(INSTALL_DIR):
        print(f"Existing installation found. Backing up to {BACKUP_DIR}.")
        log_action(f"Backing up existing installation to {BACKUP_DIR}.")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        backup_path = os.path.join(BACKUP_DIR, datetime.now().strftime('%Y%m%d%H%M%S'))
        shutil.move(INSTALL_DIR, backup_path)


def clean_install():
    """Remove the existing installation if confirmed by the user."""
    if os.path.exists(INSTALL_DIR):
        answer = input(f"Do you want to remove the existing installation at {INSTALL_DIR}? [y/n]: ").strip().lower()
        if answer == 'y':
            log_action(f"Removing existing installation at {INSTALL_DIR}")
            shutil.rmtree(INSTALL_DIR)
        else:
            print("Installation aborted.")
            log_action("Installation aborted by user.")
            sys.exit(0)


def install_fresh():
    """Create fresh target directories."""
    print(f"Creating target directories: {INSTALL_DIR}, {EOS_CONFIGS}, {EOS_LOGS}")
    log_action(f"Creating directories: {INSTALL_DIR}, {EOS_CONFIGS}, {EOS_LOGS}")
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.makedirs(EOS_CONFIGS, exist_ok=True)
    os.makedirs(EOS_LOGS, exist_ok=True)


def move_scripts():
    """Move the main script and other scripts to the target directory."""
    if not os.path.isdir(SOURCE_DIR):
        log_action(f"Error: Source directory {SOURCE_DIR} does not exist.")
        print(f"Error: Source directory {SOURCE_DIR} does not exist.")
        sys.exit(1)

    print(f"Moving scripts from {SOURCE_DIR} to {INSTALL_DIR}")
    log_action(f"Moving scripts from {SOURCE_DIR} to {INSTALL_DIR}")
    for file in os.listdir(SOURCE_DIR):
        file_path = os.path.join(SOURCE_DIR, file)
        if os.path.isfile(file_path):
            shutil.copy(file_path, INSTALL_DIR)
            os.chmod(os.path.join(INSTALL_DIR, file), 0o755)
    log_action("All scripts moved and made executable.")

# -------- SCRIPT RUNNER FUNCTIONS -------- #
def show_help():
    """Displays help information."""
    help_text = f"""
Usage: sudo eos <script_name_or_path> [options]

Options:
  --help         Show this help message and exit
  list           List all available scripts in the '{INSTALL_DIR}' directory
  --dir <path>   Specify an alternative directory for scripts

Description:
  The 'eos' command allows you to execute any script by providing its name or path.
  The script will be made executable and then run.

Examples:
  sudo eos list
    List all scripts available in the '{INSTALL_DIR}' directory.

  sudo eos <script_name>
    Run a specific script from the '{INSTALL_DIR}' directory.

  sudo eos --dir /path/to/scripts <script_name>
    Run a script from a custom directory.
"""
    print(help_text)


def list_scripts(script_dir):
    """Lists all scripts in the script directory."""
    print(f"Run any of the scripts below by running: sudo eos <example>")
    for script in os.listdir(script_dir):
        script_path = os.path.join(script_dir, script)
        if os.path.isfile(script_path):
            print(os.path.basename(script_path))


def make_executable(script_path):
    """Makes the script executable."""
    os.chmod(script_path, 0o755)


def execute_script(script_path):
    """Executes the script."""
    log_action(f"Executing script: {script_path}")
    subprocess.run([script_path], check=True)


# -------- MAIN FUNCTION -------- #
def main():
    # Check if the script is running in "install" mode
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        log_action("Starting installation process.")
        check_dependencies()
        backup_existing_install()
        clean_install()
        install_fresh()
        move_scripts()
        log_action("Installation complete.")
        print("Installation complete. Check /var/log/eos/install.log for details.")
        print('To get started, you need to run the following commands:')
        print('  export PATH="$PATH:/usr/local/bin/eos"')
        print('  source ~/.bashrc')
        sys.exit(0)

    # If not "install" mode, it's the "run" mode for executing scripts
    if len(sys.argv) < 2:
        print("Error: No script name provided.")
        show_help()
        sys.exit(1)

    args = sys.argv[1:]
    script_dir = INSTALL_DIR
    script_name = None

    while args:
        arg = args.pop(0)
        if arg == "--help":
            show_help()
            sys.exit(0)
        elif arg == "list":
            list_scripts(script_dir)
            sys.exit(0)
        elif arg == "--dir":
            if not args:
                print("Error: No directory specified with --dir option.")
                sys.exit(1)
            script_dir = args.pop(0)
        else:
            script_name = arg

    # If no script name was provided after processing options, show help
    if not script_name:
        print("Error: No script name provided.")
        show_help()
        sys.exit(1)

    # Construct script path
    if "/" not in script_name:
        script_path = os.path.join(script_dir, script_name)
    else:
        script_path = script_name

    # Check if the script exists
    if not os.path.isfile(script_path):
        print(f"Error: Script '{script_name}' not found in '{script_dir}'.")
        log_action(f"Script '{script_name}' not found in '{script_dir}'")
        sys.exit(1)

    # Make the script executable and run it
    make_executable(script_path)
    execute_script(script_path)


if __name__ == "__main__":
    main()
