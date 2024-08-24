#!/bin/bash
# run.sh

# If no argument is provided, display the usage message
if [ -z "$1" ]; then
    echo "Usage: sudo run <script_path>"
    echo ""
    echo "To see what else you can do with 'run', simply type:"
    echo "sudo run"
    echo ""
    echo "This command allows you to:"
    echo "- Execute any script by providing its path."
    echo "- The script will be made executable and then run."
    echo ""
    echo "You can also list available scripts in the scripts/ directory:"
    echo "sudo run list"
    exit 1
fi

# Handle the 'list' argument to list all scripts in the scripts/ directory
if [ "$1" == "list" ]; then
    echo "Available scripts in the scripts/ directory:"
    ls -1 ./scripts/*.sh
    exit 0
fi

script_name="$1"

# Prepend the 'scripts/' directory if the script_name doesn't contain a path
if [[ "$script_name" != */* ]]; then
    script_path="./scripts/$script_name"
else
    script_path="$script_name"
fi

# Check if the script exists
if [ ! -f "$script_path" ]; then
    echo "Error: Script '$script_name' not found."
    exit 1
fi

# Make the script executable and run it
chmod +x "$script_path"
"$script_path"
