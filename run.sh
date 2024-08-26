#!/bin/bash

# Function to list all scripts in the /usr/local/bin/fabric directory
list_scripts() {
    echo "Available scripts in /usr/local/bin/fabric:"
    if [ -d "/usr/local/bin/fabric" ]; then
        ls /usr/local/bin/fabric
    else
        echo "Directory /usr/local/bin/fabric does not exist."
    fi
}

# Check if the script argument is provided
if [ -z "$1" ]; then
  echo "Error: No script name provided."
  echo "Usage: run <script.sh>"
  exit 1
fi

# Check if the user wants to list available scripts
if [ "$1" == "list" ]; then
    list_scripts
    exit 0
fi

# Search in the current directory, /usr/local/bin/fabric, and by absolute path
if [ -f "$1" ]; then
  script_path="./$1"
elif [ -f "/usr/local/bin/fabric/$1" ]; then
  script_path="/usr/local/bin/fabric/$1"
else
  echo "Error: Script '$1' not found."
  exit 1
fi

# Make the script executable
chmod +x "$script_path"

# Run the script
"$script_path"
