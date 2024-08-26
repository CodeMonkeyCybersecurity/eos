#!/bin/bash

# Check if the script argument is provided
if [ -z "$1" ]; then
  echo "Error: No script name provided."
  echo "Usage: run <script.sh>"
  exit 1
fi

# Search in the current directory, /usr/local/bin/fabric, and by absolute path
if [ -f "$1" ]; then
  script_path="./$1"
elif [ -f "/usr/local/bin/fabric/$1" ]; then
  script_path="/usr/local/bin/fabric/$1"
elif [ -f "$(realpath "$1")" ]; then
  script_path=$(realpath "$1")
else
  echo "Error: Script '$1' not found."
  exit 1
fi

# Make the script executable
chmod +x "$script_path"

# Run the script
"$script_path"
