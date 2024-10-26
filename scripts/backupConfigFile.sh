#!/bin/bash

# Prompt for new username
read -p "Enter the file to back backed up: " fileName
backupName = "$fileName.backup.$(date +"%A_%Y-%m-%d_%H%M%S")"
read -p "Trying to create backup of $fileName now: $backupName"

# Check if the fileName is not empty
if [[ -z "$fileName" ]]; then
    echo "File name cannot be empty!"
    exit 1
fi

# Check if file exists
if [[ -f "$fileName" ]]; then
    cp "$fileName" "$backupName"
    echo "The file $fileName has been backed up as $backupName."
    echo "Keep humans in the loop"
    exit 0
else
    echo "The file $fileName does not exist!"
    exit 1
fi
