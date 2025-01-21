#!/bin/bash
# users_with_remote_ssh.sh


# Function to check which users can log in remotely using SSH
check_ssh_access() {
    echo "Users with remote SSH access:"
    awk -F':' '{ print $1 }' /etc/passwd | while read user; do
        if [[ $(sudo grep -E "^$user:.*:.*:.*:.*:.*:.*:" /etc/passwd | cut -d ':' -f7) == "/bin/bash" ]]; then
            if sudo grep -q "^AllowUsers.*\b$user\b" /etc/ssh/sshd_config; then
                echo "$user"
            fi
        fi
    done
}

# Function to allow a user remote SSH access
allow_ssh_access() {
    read -p "Do you know the username of the user you want to allow SSH access? (yes/no): " know_user

    if [[ $know_user == "yes" ]]; then
        read -p "Enter the username you want to allow SSH access: " username
    else
        read -p "Do you want to display all current users? (yes/no): " display_users

        if [[ $display_users == "yes" ]]; then
            awk -F':' '{ print $1 }' /etc/passwd
            allow_ssh_access # Loop back to asking for user input
        else
            echo "Exiting."
            exit 0
        fi
    fi

    # Confirm and allow SSH access
    read -p "Are you sure you want to allow SSH access to user $username? (yes/no): " confirm

    if [[ $confirm == "yes" ]]; then
        sudo sed -i "/^AllowUsers/s/$/ $username/" /etc/ssh/sshd_config
        sudo systemctl reload sshd
        echo "SSH access granted to user $username."
    else
        echo "Operation cancelled."
    fi
}

# Main script logic
check_ssh_access

read -p "Do you want to add any users to allow them remote SSH access? (yes/no): " add_user

if [[ $add_user == "yes" ]]; then
    allow_ssh_access
else
    echo "Exiting."
    exit 0
fi
