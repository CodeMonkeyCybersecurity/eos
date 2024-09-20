import subprocess
import sys
import os
import yaml

# Function to run shell commands and handle errors
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}")
        print(f"Error message: {e.stderr.decode('utf-8')}")
        sys.exit(1)

# Setup Fabric environment
def setup_fabric():
    print("Setting up Fabric...")
    
    # Ensure Fabric is installed
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "fabric"])
        print("Fabric installed successfully.")
    except subprocess.CalledProcessError:
        print("Error installing Fabric.")
        sys.exit(1)

    # Set up default configuration file if it doesn't exist
    config_path = '/etc/eos/fabric_config.yaml'
    if not os.path.exists(config_path):
        default_config = {
            'hosts': ['localhost'],
            'user': 'your-username',
            'tasks': ['task1', 'task2']  # Replace with your tasks
        }
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f)
        print(f"Default configuration created at {config_path}")

# Run Fabric tasks
def run_fabric_task(task):
    print(f"Running Fabric task: {task}")
    
    # Execute the Fabric command
    try:
        command = f"fab {task}"
        output = run_command(command)
        print(output)
    except Exception as e:
        print(f"Error running task: {task}. Details: {e}")
        sys.exit(1)

# Check Fabric installation and configuration
def check_fabric():
    print("Checking Fabric installation and configuration...")
    
    # Check if Fabric is installed
    try:
        output = run_command("fab --version")
        print(f"Fabric version: {output}")
    except Exception:
        print("Fabric is not installed.")
        sys.exit(1)
    
    # Check for config file
    config_path = '/etc/eos/fabric_config.yaml'
    if os.path.exists(config_path):
        print(f"Fabric configuration found at {config_path}.")
    else:
        print(f"Fabric configuration not found at {config_path}. Run setup to create one.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 eos_fabric.py <setup|run|check> [task_name]")
        sys.exit(1)

    action = sys.argv[1]

    if action == "setup":
        setup_fabric()
    elif action == "run":
        if len(sys.argv) < 3:
            print("Please provide the Fabric task name.")
            sys.exit(1)
        run_fabric_task(sys.argv[2])
    elif action == "check":
        check_fabric()
    else:
        print("Unknown command. Use <setup|run|check>.")
        sys.exit(1)
