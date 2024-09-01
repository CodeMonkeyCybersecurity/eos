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

USER=$(whoami)
echo "Hello, $USER"

LOG_DIR=/home/$USER/fabric/logs
echo "the log directory is: $LOG_DIR"

# set variables
set_variables() {
    FILE_NAME='manageCron.txt'
    LOG_FILE=$LOG_DIR/$FILE_NAME
    touch $LOG_FILE
    echo "Your logs are: $LOG_FILE"
}

# edit crontab 
edit_cron() {
    echo "editting crontab with nano"
    sudo crontab -e nano >> $CRON_TIME $CRON_CMD 
}

cron_time() {
    echo "You need to set the time you want this command to run during the week."
    read -p "enter the minute (0-59), * for nil/all: " MIN
    read -p "enter the hour (0-23), * for nil/all: " HR
    read -p "enter the day of the month (1-31), * for nil/all: " DATE
    read -p "enter the month (1-12), * for nil/all: " MONTH
    read -p "enter Day of the week (0-7, where 0 or 7 is Sunday), * for nil/all: " DAY
    CRON_TIME='$(MIN) $(HR) $(DATE) $(MONTH) $(WEEK)'
    echo "you entered: $(CRON_TIME)"
}

cron_command() {
    read -p "What is the command you want to execute: " CMD
    CRON_CMD="$CMD >> /var/log/cron_command.txt"
    echo "Your command is $(CRON_CMD)"
}

cron_path () {
    echo "your current PATH is: "
    echo $PATH
    if ask_Yn "do you want to add $(PATH) to your crontab?"; then
        sudo crontab -e nano >> $PATH
        echo "$PATH added."
    else 
        echo "not added."
    fi
}

cron_backup () {
    if ask_Yn "Do you wan to back up your crontab?"; then
        crontab -l > mycron_backup.txt
        echo "mycron_backup.txt created"
    else
        echo "backup not created"
    fi
}

cron_logrotate () {
    if ask_Yn "Do you want to rotate your logs every day?"; then 
        LOGROTATE="0 0 * * * /usr/sbin/logrotate /etc/logrotate.conf >> /var/log/logrotate.log 2>&1"
        sudo crontab -e nano >> $LOGROTATE
    else 
       "daily log rotn not added."
    fi
}


set_variables &> $LOG_FILE
cron_backup &> $LOG_FILE
cron_logrotate &> $LOG_FILE
cron_time &> $LOG_FILE
cron_command &> $LOG_FILE
edit_cron &> $LOG_FILE

crontab -l
grep CRON /var/log/syslog
echo "done"

