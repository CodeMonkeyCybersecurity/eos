#!/bin/bash

# Function to get the current user's name
get_username() {
    echo "$(whoami)"
}

# Function to check if 'run' command exists
check_run_exists() {
    if [ -f "/usr/local/bin/run" ]; then
        echo "'run' command already exists in /usr/local/bin."
        return 0
    else
        return 1
    fi
}

# Function to confirm the current directory is correct
confirm_directory() {
    current_dir=$(pwd)
    echo "Current directory is: $current_dir"
    read -p "Is this the correct directory where 'MonQ-fabric' is cloned? (y/n): " confirm_dir
    if [[ ! "$confirm_dir" =~ ^[Yy]$ ]]; then
        echo "Please navigate to the correct directory and run the script again."
        exit 1
    fi
}

# Function to create the 'run' command using the run.sh from the repository
create_run_command() {
    cp "$1/run.sh" /usr/local/bin/run
    chmod +x /usr/local/bin/run
    echo "'run' command has been successfully created from run.sh and installed in /usr/local/bin."
}

# Function to ensure all scripts in the scripts/ directory are executable
make_scripts_executable() {
    script_dir="$1/scripts"
    if [ -d "$script_dir" ]; then
        echo "Making all scripts in $script_dir executable..."
        chmod +x "$script_dir"/*
        echo "All scripts in $script_dir are now executable."
    else
        echo "Error: scripts directory not found at $script_dir."
        exit 1
    fi
}

# Main script execution
echo "This script will install the 'run' command for the current user: $(get_username) and for root."

read -p "Do you want to continue? (y/n): " confirm
if [[ "$confirm" =~ ^[Yy]$ ]]; then
    check_run_exists
    if [ $? -eq 0 ]; then
        read -p "Do you want to overwrite the existing 'run' command? (y/n): " overwrite
        if [[ ! "$overwrite" =~ ^[Yy]$ ]]; then
            echo "Exiting without making changes."
            exit 1
        fi
    fi

    confirm_directory
    make_scripts_executable "$current_dir"
    create_run_command "$current_dir"

    echo "'run' command has been installed and can be executed from any directory."
else
    echo "Installation cancelled by user."
    exit 1
fi
