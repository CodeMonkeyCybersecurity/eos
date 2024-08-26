#!/bin/bash
# run.sh

# Get the directory where this script is located
script_dir="$(dirname "$(realpath "$0")")/../scripts"

# If no argument is provided, display the usage message
if [ -z "$1" ]; then
    echo "Usage: sudo run <script_name_or_path>"
    echo ""
    echo "To see what else you can do with 'run', simply type:"
    echo "sudo run"
    echo ""
    echo "This command allows you to:"
    echo "- Execute any script by providing its name or path."
    echo "- The script will be made executable and then run."
    echo ""
    echo "You can also list available scripts in the scripts/ directory:"
    echo "sudo run list"
    exit 1
fi

# Handle the 'list' argument to list all scripts in the scripts/ directory
if [ "$1" == "list" ]; then
    echo "Run any of the scripts below by running: sudo run <example>"
    for script in "$script_dir"/*.sh; do
        basename "$script" .sh
    done
    exit 0
fi

script_name="$1"

# If the script_name doesn't contain a path, prepend the 'scripts/' directory
if [[ "$script_name" != */* ]]; then
    script_path="$script_dir/$script_name.sh"
else
    script_path="$script_name"
fi

# Check if the script exists
if [ ! -f "$script_path" ]; then
    echo "Error: Script '$script_name' not found in '$script_dir'."
    exit 1
fi

# Make the script executable and run it
chmod +x "$script_path"
"$script_path"
