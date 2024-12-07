import sys
import os

# Dynamically add the `scripts` directory to Python's module search path
current_dir = os.path.dirname(os.path.abspath(__file__))  # Path to current script
scripts_dir = os.path.abspath(os.path.join(current_dir, "../../.."))  # Navigate to `scripts`
sys.path.insert(0, scripts_dir)

# Now you can import from commonUtils
from commonUtils.checkSudo import check_sudo
from commonUtils.checkDependencies import check_dependencies
from commonUtils.runCommand import run_command

def main():
    check_sudo()
    check_dependencies()
    run_command("echo 'Setup complete!'", "Failed to complete setup.")

if __name__ == "__main__":
    main()
