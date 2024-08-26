#!/bin/bash

# Function to validate cron schedule format
function validate_cron_format() {
    local cron="$1"
    if [[ "$cron" =~ ^(\*|[0-9]+|\*/[0-9]+)(\s+(\*|[0-9]+|\*/[0-9]+)){4}$ ]]; then
        return 0
    else
        echo "Invalid cron format. Please use the correct cron schedule syntax."
        return 1
    fi
}

# Function to add a new cron job
function add_cron_job() {
    local schedule="$1"
    local command="$2"
    local cron_entry="${schedule} ${command}"
    
    # Ask if the user wants to edit the existing crontab or append
    echo "Would you like to edit the existing crontab or append the new entry?"
    echo "1. Edit existing crontab"
    echo "2. Append new entry"
    read -p "Choose an option (1 or 2): " choice

    if [[ "$choice" == "1" ]]; then
        crontab -e
        echo "Please manually add the following entry to your crontab:"
        echo "$cron_entry"
    elif [[ "$choice" == "2" ]]; then
        # Backup current crontab
        crontab -l > mycron
        echo "$cron_entry" >> mycron
        crontab mycron
        rm mycron
        echo "New cron job added."
    else
        echo "Invalid choice. Exiting."
        exit 1
    fi
}

# Prompt user for cron schedule
while true; do
    read -p "Enter the cron schedule (e.g., '*/5 * * * *' for every 5 minutes): " cron_schedule
    validate_cron_format "$cron_schedule"
    if [[ $? -eq 0 ]]; then
        break
    fi
done

# Prompt user for the command to run
read -p "Enter the command you want to schedule: " cron_command

# Confirm with the user
echo "You are about to add the following cron job:"
echo "${cron_schedule} ${cron_command}"
read -p "Do you want to proceed? (y/n): " confirm

if [[ "$confirm" =~ ^[Yy]$ ]]; then
    add_cron_job "$cron_schedule" "$cron_command"
else
    echo "Operation cancelled."
fi
