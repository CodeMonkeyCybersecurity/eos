#!/bin/bash
# test.sh

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

# Check schema permissions
sudo -u eos_user psql -d eos_db -c "\dn+"   # Check schema permissions
echo "Press Enter to continue..."
read -r

# List tables in the eos_db
sudo -u eos_user psql -d eos_db -c "\dt"   # List tables in the eos_db
echo "Press Enter to continue..."
read -r

# verify that eos_user has the required privileges
sudo -u eos_user psql -d eos_db -c "\z"
echo "Press Enter to continue..."
read -r

# List the contents of the cyberMonkey log directory
sudo ls -lah /var/log/cyberMonkey/
echo "Press Enter to continue..."
read -r

# Display the eos.log file
sudo cat /var/log/cyberMonkey/eos.log
echo "Press Enter to continue..."
read -r