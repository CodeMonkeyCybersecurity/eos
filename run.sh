#!/bin/bash
# run.sh

# Define the directory where the scripts are located
script_dir="/usr/local/bin/fabric"

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
    echo "You can also list available scripts in the '$script_dir' directory:"
    echo "sudo run list"
    exit 1
fi

# Handle the 'list' argument to list all scripts in the script_dir directory
if [ "$1" == "list" ]; then
    echo "Run any of the scripts below by running: sudo run <example>"
    # List all files in the directory, filtering out directories
    ls -lah /usr/local/bin/fabric
        fi
    done
    exit 0
fi

script_name="$1"

# If the script_name doesn't contain a path, prepend the script_dir directory
if [[ "$script_name" != */* ]]; then
    script_path="$script_dir/$script_name"
else
    script_path="$script_name"
fi

# Check if the script exists
if [ ! -f "$script_path" ]; then
    echo "Error: Script '$script_name' not found in '$script_dir'."
    exit 1
fi

# Make the script executable
chmod +x "$script_path"

# Run the script
"$script_path"
