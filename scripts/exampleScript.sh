#!/bin/bash

# Example Bash Script: Backup Script

# Set variables
BACKUP_DIR="/backup"
SOURCE_DIR="/data"
LOG_FILE="/backup/backup.log"

# Function to log messages
log_message() {
    echo "$(date): $1" >> "$LOG_FILE"
}

# Check if backup directory exists
if [ ! -d "$BACKUP_DIR" ]; then
    log_message "Creating backup directory."
    mkdir -p "$BACKUP_DIR"
fi

# Perform backup
log_message "Starting backup of $SOURCE_DIR to $BACKUP_DIR."
cp -r "$SOURCE_DIR"/* "$BACKUP_DIR/"

# Check if the backup was successful
if [ $? -eq 0 ]; then
    log_message "Backup completed successfully."
else
    log_message "Backup failed!"
fi
