#!/bin/bash
# change_users_password.sh

# Ask for the user's name
read -p "Enter the username whose password you want to change: " username

# Ask for the new password
read -sp "Enter the new password for $username: " new_password
echo

# Change the user's password
echo "$username:$new_password" | sudo chpasswd

# Check if the password change was successful
if [ $? -eq 0 ]; then
  echo "Password for user $username has been successfully changed."
else
  echo "Failed to change the password for user $username."
fi