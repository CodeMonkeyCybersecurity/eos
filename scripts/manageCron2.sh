#!/bin/bash

# Function to ask a Y/n question
ask_Yn() {
    local prompt="$1"  # The question to ask
    local default="${2:-Y}"  # Default value if the user presses Enter (Y by default)
    local response

    # Determine the prompt format
    if [[ "$default" == "Y" || "$default" == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    # Read user input
    while true; do
        read -r -p "$prompt" response
        # Use the default if no response is provided
        if [[ -z "$response" ]]; then
            response="$default"
        fi

        case "$response" in
            [Yy]*)  # Yes cases
                return 0  # Indicates 'Yes'
                ;;
            [Nn]*)  # No cases
                return 1  # Indicates 'No'
                ;;
            *)  # Invalid input
                echo "Please enter Y or n."
                ;;
        esac
    done
}

# Set user and log directory
USER=$(whoami)
echo "Hello, $USER"

if [ "$USER" = "root" ]; then
    LOG_DIR="/root/fabric/logs"
else
    LOG_DIR="/home/$USER/fabric/logs"
fi
echo "The log directory is: $LOG_DIR"

# Set variables
set_variables() {
    FILE_NAME='manageCron.txt'
    LOG_FILE="$LOG_DIR/$FILE_NAME"
    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
    echo "Your logs are: $LOG_FILE"
}

# Edit crontab
edit_cron() {
    echo "Editing crontab with nano"
    (crontab -l 2>/dev/null; echo "$CRON_TIME $CRON_CMD") | crontab -
    echo "Crontab updated."
}

# Set cron time
cron_time() {
    echo "You need to set the time you want this command to run during the week."
    read -p "Enter the minute (0-59), * for nil/all: " MIN
    read -p "Enter the hour (0-23), * for nil/all: " HR
    read -p "Enter the day of the month (1-31), * for nil/all: " DATE
    read -p "Enter the month (1-12), * for nil/all: " MONTH
    read -p "Enter the day of the week (0-7, where 0 or 7 is Sunday), * for nil/all: " DAY
    CRON_TIME="$MIN $HR $DATE $MONTH $DAY"
    echo "You entered: $CRON_TIME"
}

# Set cron command
cron_command() {
    read -p "What is the command you want to execute: " CMD
    CRON_CMD="$CMD >> /var/log/cron_command.txt 2>&1"
    echo "Your command is $CRON_CMD"
}

# Add PATH to crontab
cron_path () {
    echo "Your current PATH is: $PATH"
    if ask_Yn "Do you want to add the current PATH to your crontab?"; then
        (crontab -l 2>/dev/null; echo "PATH=$PATH") | crontab -
        echo "PATH added."
    else
        echo "Not added."
    fi
}

# Backup crontab
cron_backup () {
    if ask_Yn "Do you want to back up your crontab?"; then
        crontab -l > mycron_backup.txt
        echo "mycron_backup.txt created"
    else
        echo "Backup not created"
    fi
}

# Set up log rotation in crontab
cron_logrotate () {
    if ask_Yn "Do you want to rotate your logs every day?"; then
        LOGROTATE="0 0 * * * /usr/sbin/logrotate /etc/logrotate.conf >> /var/log/logrotate.log 2>&1"
        (crontab -l 2>/dev/null; echo "$LOGROTATE") | crontab -
        echo "Log rotation added."
    else
        echo "Daily log rotation not added."
    fi
}

# Run functions and log output
set_variables &> "$LOG_FILE"
cron_backup &> "$LOG_FILE"
cron_logrotate &> "$LOG_FILE"
cron_time &> "$LOG_FILE"
cron_command &> "$LOG_FILE"
edit_cron &> "$LOG_FILE"
cron_path &> "$LOG_FILE"

# Display current crontab
crontab -l

# Display cron log entries from syslog
grep CRON /var/log/syslog

echo "done"
