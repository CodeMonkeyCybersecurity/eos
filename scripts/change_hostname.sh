#!/bin/bash
# change_hostname.sh

# Display the current hostname
current_hostname=$(hostname)
echo "The current hostname is: $current_hostname"

# Ask for confirmation to proceed
read -p "Do you want to change the hostname? (yes/no) " confirm

if [[ $confirm =~ ^[Yy][Ee][Ss]$ ]]
then
    # Ask for the new hostname
    read -p "Enter the new hostname: " new_hostname

    # Check if the input is not empty
    if [[ -z "$new_hostname" ]]
    then
        echo "The hostname cannot be empty!"
        exit 1
    fi

    # Change the hostname temporarily
    sudo hostname $new_hostname

    # Change the hostname permanently
    echo $new_hostname | sudo tee /etc/hostname > /dev/null

    # Update /etc/hosts file
    sudo sed -i "s/$current_hostname/$new_hostname/g" /etc/hosts

    echo "Hostname changed successfully to $new_hostname"
else
    echo "Hostname change aborted."
fi
