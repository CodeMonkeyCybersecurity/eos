#!/bin/bash

# Function to prompt user for input with a default value
prompt_user() {
    local prompt_text="$1"
    local default_value="$2"
    local input

    read -p "$prompt_text [$default_value]: " input
    echo "${input:-$default_value}"
}

# Function to validate the directory path
validate_directory() {
    local dir_path="$1"
    if [[ ! -d "$dir_path" ]]; then
        echo "Error: The directory '$dir_path' does not exist."
        exit 1
    fi
}

# Function to reload Bareos services
reload_bareos_services() {
    echo "Reloading Bareos services to apply your configuration changes..."
    systemctl reload bareos-dir
    systemctl reload bareos-fd
    systemctl reload bareos-sd
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to reload Bareos services."
        exit 1
    fi
    echo "Bareos services reloaded successfully."
}

# Explanation of what the script does
echo "This script will configure Bareos by asking you for key information such as the Director, Client, and Storage names, as well as passwords and the backup directory path."

# Prompt user for configuration details
echo "The Bareos Director is the central server component that controls the backup operations."
director_name=$(prompt_user "Enter the Bareos Director name" "bareos-dir")

echo "The Bareos FileDaemon is the component installed on the client machines to be backed up."
fd_name=$(prompt_user "Enter the Bareos FileDaemon (Client) name" "bareos-fd")

echo "The Bareos Storage component manages where and how the backups are stored."
storage_name=$(prompt_user "Enter the Bareos Storage name" "bareos-sd")

echo "The Director password is used by the Director to authenticate with other Bareos components."
director_password=$(prompt_user "Enter the Director password" "password")

echo "The FileDaemon password is used by the FileDaemon to authenticate with the Director."
fd_password=$(prompt_user "Enter the FileDaemon (Client) password" "password")

echo "The backup directory path is where the backups will be stored."
backup_dir=$(prompt_user "Enter the backup directory path" "/var/lib/bareos")
validate_directory "$backup_dir"  # Validate the backup directory

# Display collected information with explanation
echo "Here are the configuration details you provided:"
echo "Director Name: $director_name  # Bareos Director, the central server component."
echo "FileDaemon Name: $fd_name  # Bareos FileDaemon, installed on client machines."
echo "Storage Name: $storage_name  # Bareos Storage, manages backup storage."
echo "Director Password: $director_password  # Password for Director authentication."
echo "FileDaemon Password: $fd_password  # Password for FileDaemon authentication."
echo "Backup Directory: $backup_dir  # Directory on the client machine for storing backups."

# Confirm the details
read -p "Is this information correct? (y/n): " confirm

if [[ "$confirm" != "y" ]]; then
    echo "Aborting configuration."
    exit 1
fi

# Create Bareos Director configuration file
cat <<EOF > /etc/bareos/bareos-dir.conf
Director {
    Name = $director_name
    Password = "$director_password"
}

Storage {
    Name = $storage_name
    Address = localhost
    Password = "$director_password"
}

Client {
    Name = $fd_name
    Address = localhost
    Password = "$fd_password"
}

JobDefs {
    Name = "DefaultJob"
    Type = Backup
    FileSet="Full Set"
    Schedule = "WeeklyCycle"
    Storage = $storage_name
    Messages = Standard
    Pool = Default
    Full Backup Pool = Default
    Differential Backup Pool = Default
    Incremental Backup Pool = Default
}

Job {
    Name = "BackupClient1"
    JobDefs = "DefaultJob"
    Client=$fd_name
    FileSet="Full Set"
}

FileSet {
    Name = "Full Set"
    Include {
        Options {
            signature = MD5
        }
        File = $backup_dir
    }
}
EOF

# Check if the configuration file was created successfully
if [[ $? -ne 0 ]]; then
    echo "Error: Failed to write the Bareos Director configuration file."
    exit 1
fi

# Reload Bareos services
reload_bareos_services

echo "Bareos configuration completed successfully. Your backup system is now configured with the provided details."
