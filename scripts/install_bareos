#!/bin/bash

# Function to display a message and exit with an error code
function error_exit {
    echo "Error: $1" 1>&2
    exit 1
}

# Function to display a message
function info_message {
    echo "Info: $1"
}

# Check if the script is run as root
if [[ $EUID -ne 0 ]]; then
   error_exit "This script must be run as root."
fi

# Open firewall port 5432 for PostgreSQL
info_message "Allowing connections on port 5432..."
sudo ufw allow 5432 || error_exit "Failed to open port 5432."

apt install postgresql

# Define PostgreSQL version
PG_VERSION="16"

# Define configuration file paths
PG_CONF="/etc/postgresql/$PG_VERSION/main/postgresql.conf"
PG_HBA="/etc/postgresql/$PG_VERSION/main/pg_hba.conf"

# Backup the original configuration files before making changes
info_message "Backing up configuration files..."
cp "$PG_CONF" "${PG_CONF}.backup" || error_exit "Failed to back up $PG_CONF"
cp "$PG_HBA" "${PG_HBA}.backup" || error_exit "Failed to back up $PG_HBA"

# Update listen_addresses in postgresql.conf
info_message "Configuring listen_addresses in $PG_CONF..."
sed -i "s/^#listen_addresses.*/listen_addresses = '*'/" "$PG_CONF" || error_exit "Failed to update listen_addresses in $PG_CONF"

# Update pg_hba.conf to allow connections from all IP addresses
info_message "Configuring client access in $PG_HBA..."
cat <<EOL > "$PG_HBA"
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Allow local connections:
local   all             all                                     peer
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5

# Allow connections from any IP address:
host    all             all             0.0.0.0/0               md5
host    all             all             ::/0                    md5
EOL

if [[ $? -ne 0 ]]; then
    error_exit "Failed to update $PG_HBA"
fi

# Restart PostgreSQL to apply changes
info_message "Restarting PostgreSQL..."
sudo systemctl restart postgresql || error_exit "Failed to restart PostgreSQL"

# Check if PostgreSQL is listening on the correct port
info_message "Checking if PostgreSQL is listening on port 5432..."
sudo ss -ltn | grep 5432 || error_exit "PostgreSQL is not listening on port 5432"

# Display PostgreSQL service status
info_message "Checking PostgreSQL service status..."
sudo systemctl status postgresql --no-pager || error_exit "Failed to get PostgreSQL service status."

# Install Bareos
info_message "Adding Bareos repositories and installing Bareos..."
curl -fsSL https://download.bareos.org/current/xUbuntu_22.04/add_bareos_repositories.sh | sh || error_exit "Failed to add Bareos repositories."
sudo apt update || error_exit "Failed to update package lists."
sudo apt install -y bareos || error_exit "Failed to install Bareos."

info_message "Bareos installation and PostgreSQL configuration completed successfully."
