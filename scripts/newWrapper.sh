#!/bin/bash

set -x  # Enable debugging

# Logs function to set up logging
logs () {
    FILE_NAME="newWrapper.sh"
    LOG_DIR="/var/log/fabric"
    LOG_FILE="$LOG_DIR/$FILE_NAME"
    
    # Ensure log directory exists
    sudo mkdir -p "$LOG_DIR"
    sudo touch "$LOG_FILE"
    echo "Your logs are: $LOG_FILE"
}

# Function to ask a Y/n question
ask() {
    local prompt="$1"  # The question to ask
    local default="${2:-Y}"  # Default value if the user presses Enter (Y by default)
    local response

    # Determine the prompt format
    if [[ "$default" == "Y" || "$default" == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    # Read user input
    while true; do
        read -r -p "$prompt" response
        # Use the default if no response is provided
        if [[ -z "$response" ]]; then
            response="$default"
        fi

        case "$response" in
            [Yy]*)  # Yes cases
                return 0  # Indicates 'Yes'
                ;;
            [Nn]*)  # No cases
                return 1  # Indicates 'No'
                ;;
            *)  # Invalid input
                echo "Please enter Y or n."
                ;;
        esac
    done
}

# Function to create a new wrapper using `cat`
wrap_name () {
    read -p "What is the name of the new wrapper you want to create (e.g., newWrapper.sh): " NAME

    # Check if the name is not empty
    if [[ -z "$NAME" ]]; then
        echo "Wrapper name cannot be empty. Exiting."
        exit 1
    fi

    # Create file using `cat` to avoid interactive editor hanging
    echo "Enter the content of the new wrapper. Press Ctrl+D to save."
    cat > "$NAME"
    
    # Ensure the file was created successfully
    if [ $? -ne 0 ]; then
        echo "Failed to create $NAME." >&2  # Redirect error message to stderr
        exit 1
    fi

    echo "Making $NAME executable."
    chmod +x "$NAME" 2>> "$LOG_FILE"  # Redirect stderr to log file
}

# Function to test the new wrapper
test_wrap () {
    if [[ -z "$NAME" ]]; then
        echo "No wrapper name provided. Exiting."
        exit 1
    fi

    if ask "Do you want to test $NAME now?"; then
        if [ -f "./$NAME" ]; then
            ./"$NAME" 2>> "$LOG_FILE"  # Redirect stderr to log file
            if [ $? -ne 0 ]; then
                echo "Error occurred while testing $NAME." >&2  # Redirect error message to stderr
                exit 1
            fi
            echo "$NAME tested."
        else
            echo "File $NAME does not exist or is not executable."
        fi
    else
        echo "Not testing."
    fi
}

# Main script execution
logs
wrap_name  # Redirect stderr to log file
test_wrap  # Redirect stderr to log file

echo "done"

set +x  # Disable debugging
