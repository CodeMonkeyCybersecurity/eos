#!/bin/bash

# Function to check if a command is installed
checkIfInstalled() {
    local command_name=$1
    local install_hint=${2:-"Please install $command_name using your package manager."}

    # Check if the command exists
    if ! command -v "$command_name" &> /dev/null; then
        echo "[ERROR] '$command_name' is not installed."
        echo "$install_hint"
        return 1 # Return error code
    else
        echo "[OK] '$command_name' is installed."
        return 0 # Return success code
    fi
}

# Example usage of the submodule (can be commented out when used as a submodule)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Sample commands to check
    checkIfInstalled "curl" "Try installing curl using 'sudo apt install curl' (Debian/Ubuntu) or 'brew install curl' (macOS)."
    checkIfInstalled "git"
fi
