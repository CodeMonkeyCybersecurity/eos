#!/bin/bash
# /utilities/apt.sh
source "$UTILITIES_DIR/checkSudo.sh"
echo -e "Before you do this, it's a good idea to update apt.\n"
echo "Please choose an option from the list below:"
# Define the list of options
options=("Update only" "Update and upgrade" "Update, upgrade, cleanup" "Quit")
PS3="Enter your choice: " # Prompt message
# Use the select command to display the options
select choice in "${options[@]}"; do
    case $choice in
        "Update only")
            echo "Running: apt update"
            apt update
            break
            ;;
        "Update and upgrade")
            echo "Running: apt update && apt upgrade -y"
            apt update && apt upgrade -y
            break
            ;;
        "Update, upgrade, cleanup")
            echo "Running: apt update && apt upgrade -y && apt autoremove -y && apt autoclean"
            apt update && apt upgrade -y && apt autoremove -y && apt autoclean
            break
            ;;
        "Quit")
            echo "Exiting."
            exit 0
            ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
done