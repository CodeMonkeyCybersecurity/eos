#!/bin/bash 
# Function to check if the script is being run as root
checkSudo() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "\033[31m✘ This script must be run as sudo. Please use sudo <your command>.\033[0m"
        exit 1
    else
        echo -e "\033[32m✔ Running with sudo.\033[0m"
    fi
}
# Code to execute when the script is run directly
checkSudo
