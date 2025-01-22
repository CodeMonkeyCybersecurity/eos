#!/bin/bash

# Check if a session name is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: mnemosyne <session_name>"
  exit 1
fi

# Get the session name from the argument
session_name="$1"

# Generate the current date, time, and machine name
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
machine_name=$(hostname)
user=$(whoami)

# Construct the output file name
output_file="${timestamp}_${session_name}_${user}_${machine_name}.typescript"

# Start recording the terminal session with the generated file name
script "$output_file"

# Inform the user of the output file name
echo "Terminal session has been recorded to: $output_file"

echo "finis"
