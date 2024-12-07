#!/bin/bash
# TODO : move to usr/bin/env to create CLI variable  

logError() {
    local errorMessage="$1"
    local logDir="./logs"
    local logFile="$logDir/error.log"

    # Create the logs directory if it doesn't exist
    if [ ! -d "$logDir" ]; then
        mkdir -p "$logDir"
    fi

    # Get the current timestamp
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Format the log entry
    local logEntry
    logEntry="[$timestamp] ERROR: $errorMessage"

    # Append the error message to the log file
    echo "$logEntry" >> "$logFile"

    # Output the error to the console
    echo "An error occurred: $errorMessage" >&2
}

# Example usage
logError "This is a sample error message"
# Get the original directory (where the script is run from)
ORIGINAL_DIR=$(pwd)

check_sudo() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "\e[31m✘ This script must be run as root. Please use sudo.\e[0m"
    exit 1
  else
    echo -e "✔ Running as root."
  fi
}

# Ensure the script is run as root
check_sudo

# Erase previous install
rm -rf /usr/local/bin/eos

# Create the target directory
mkdir -p /usr/local/bin/eos

# Move contents of the original directory to /usr/local/bin/eos
cp "$ORIGINAL_DIR"/* /usr/local/bin/eos/

# Make the files executable
chmod +x /usr/local/bin/eos
chmod +x /usr/local/bin/eos/scripts/*.sh || echo "No scripts found in /usr/local/bin/eos/scripts/"

echo -e "\e[32m✔ Installation complete.\e[0m"
