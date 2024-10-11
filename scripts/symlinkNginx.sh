#!/bin/bash

# Ask the user for the site configuration file name
read -p "Enter the Nginx site configuration file name (without the path): " site_name

# Define the source and destination paths
source_path="/etc/nginx/sites-available/$site_name"
destination_path="/etc/nginx/sites-enabled/$site_name"

# Check if the source configuration file exists
if [ -f "$source_path" ]; then
  # Create a symbolic link from sites-available to sites-enabled
  sudo ln -s "$source_path" "$destination_path"
  echo "Symbolic link created: $source_path -> $destination_path"
else
  echo "Error: The configuration file $site_name does not exist in /etc/nginx/sites-available."
fi
