#!/bin/bash

# Function: ask_yes_no
# Usage: ask_yes_no "Your question here" [default_answer]
# Returns: 0 (yes), 1 (no)

ask_yes_no() {
    local prompt="$1"
    local default_answer="${2:-}"
    local answer

    while true; do
        # Set the prompt based on the default answer
        case "$default_answer" in
            [Yy]* )
                read -p "$prompt [Y/n]: " answer
                answer="${answer:-Y}"
                ;;
            [Nn]* )
                read -p "$prompt [y/N]: " answer
                answer="${answer:-N}"
                ;;
            * )
                read -p "$prompt [y/n]: " answer
                ;;
        esac

        # Evaluate the user's answer
        case "$answer" in
            [Yy]* )
                return 0  # Yes
                ;;
            [Nn]* )
                return 1  # No
                ;;
            * )
                echo "Please answer yes or no."
                ;;
        esac
    done
}
