import os
import sys
import subprocess
from datetime import datetime

# Default script directory
SCRIPT_DIR = os.getenv("RUN_SCRIPT_DIR", "/usr/local/bin/eos")
LOG_FILE = "/var/log/run_script.log"


def log_action(message):
    """Logs actions to a specified log file."""
    # Ensure that the log directory exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'a') as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")


def show_help():
    """Displays help information."""
    help_text = """
Usage: sudo run <script_name_or_path> [options]

Options:
  --help         Show this help message and exit
  list           List all available scripts in the '{}' directory
  --dir <path>   Specify an alternative directory for scripts

Description:
  The 'run' command allows you to execute any script by providing its name or path.
  The script will be made executable and then run.

Examples:
  sudo run list
    List all scripts available in the '{}' directory.

  sudo run <script_name>
    Run a specific script from the '{}' directory.

  sudo run --dir /path/to/scripts <script_name>
    Run a script from a custom directory.
""".format(SCRIPT_DIR, SCRIPT_DIR, SCRIPT_DIR)
    print(help_text)


def list_scripts(script_dir):
    """Lists all scripts in the script directory."""
    print(f"Run any of the scripts below by running: sudo run <example>")
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


def main():
    # Check for no arguments
    if len(sys.argv) < 2:
        print("Error: No script name provided.")
        show_help()
        sys.exit(1)

    # Argument parsing
    args = sys.argv[1:]
    script_dir = SCRIPT_DIR
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

    # Make the script executable
    make_executable(script_path)

    # Run the script
    execute_script(script_path)


if __name__ == "__main__":
    main()
