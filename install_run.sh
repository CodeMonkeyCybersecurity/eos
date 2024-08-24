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

# Function to find MonQ-fabric repository
find_monq_fabric() {
    read -p "Enter the path where 'MonQ-fabric' repository is cloned: " monq_fabric_path
    if [ ! -d "$monq_fabric_path" ]; then
        echo "Error: Directory '$monq_fabric_path' does not exist. Please try again."
        exit 1
    fi
}

# Function to create the 'run' script
create_run_script() {
    cat <<EOL > /usr/local/bin/run
#!/bin/bash
# Navigate to MonQ-fabric directory and execute the script
cd "$1" || exit 1
chmod +x "\$1"
./"\$1"
EOL
    chmod +x /usr/local/bin/run
    echo "'run' command has been successfully created and hardcoded with the MonQ-fabric location."
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

    find_monq_fabric
    create_run_script "$monq_fabric_path"

    echo "'run' command has been installed and can be executed from any directory."
else
    echo "Installation cancelled by user."
    exit 1
fi
