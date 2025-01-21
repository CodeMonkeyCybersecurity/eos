#!/bin/bash

# Function to ensure the user is running the script with superuser privileges
function require_root {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit
    fi
}

require_root

# Prompt for new username
read -p "Enter the new username: " username

# Check if the username is not empty
if [[ -z "$username" ]]; then
    echo "Username cannot be empty!"
    exit 1
fi

# Check if user already exists
if id "$username" &>/dev/null; then
    echo "User $username already exists!"
    exit 1
fi

# Prompt for password
read -s -p "Enter the password: " password
echo

# Confirm password
read -s -p "Confirm password: " password2
echo

# Check if passwords match
if [ "$password" != "$password2" ]; then
    echo "Passwords do not match!"
    exit 1
fi

# Add user
useradd -m -s /bin/bash "$username"

# Set the user password
echo "$username:$password" | chpasswd

# Ask for sudo privileges
read -p "Should this user have sudo privileges? (yes/no): " grantsudo

if [[ $grantsudo =~ ^[Yy][Ee][Ss]$ ]]; then
    usermod -aG sudo "$username"
    echo "$username has been granted sudo privileges."
fi

echo "User $username created successfully."
