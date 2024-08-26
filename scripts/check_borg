#!/bin/bash

# Set up log file
LOGFILE=~/borgbackup/check_borg.log
echo "BorgBackup Check Log - $(date)" > $LOGFILE

# Function to log and handle errors
error_exit() {
    echo "$1" | tee -a $LOGFILE 1>&2
    exit 1
}

# Function to check if BorgBackup is installed
check_borg_installed() {
    echo "Checking if BorgBackup is installed..." | tee -a $LOGFILE
    if ! command -v borg &> /dev/null; then
        error_exit "BorgBackup is not installed. Please install it first."
    else
        echo "BorgBackup is installed." | tee -a $LOGFILE
    fi
}

# Function to check BorgBackup logs
check_logs() {
    if [ -f ~/borgbackup/backup.log ]; then
        echo "Displaying BorgBackup logs:" | tee -a $LOGFILE
        cat ~/borgbackup/backup.log | tee -a $LOGFILE
    else
        echo "Log file not found." | tee -a $LOGFILE
    fi
}

# Function to verify backup archives
verify_archives() {
    check_borg_installed
    if [ -z "$BORG_REPO" ]; then
        error_exit "BORG_REPO is not set. Exiting."
    fi
    echo "Listing archives in the repository:" | tee -a $LOGFILE
    borg list "$BORG_REPO" | tee -a $LOGFILE
}

# Function to test restore
test_restore() {
    check_borg_installed
    if [ -z "$BORG_REPO" ]; then
        error_exit "BORG_REPO is not set. Exiting."
    fi
    read -p "Enter the archive name to restore: " archive_name
    read -p "Enter the destination directory: " dest_dir
    echo "Restoring archive $archive_name to $dest_dir" | tee -a $LOGFILE
    borg extract "$BORG_REPO::$archive_name" "$dest_dir" | tee -a $LOGFILE
    echo "Restore operation completed." | tee -a $LOGFILE
}

# Function to check crontab entries
check_crontab() {
    echo "Current crontab entries for the user:" | tee -a $LOGFILE
    crontab -l | tee -a $LOGFILE
}

# Function to review borg_configs.md
review_configs() {
    if [ -f ~/borgbackup/borg_configs.md ]; then
        echo "Displaying borg_configs.md:" | tee -a $LOGFILE
        cat ~/borgbackup/borg_configs.md | tee -a $LOGFILE
    else
        echo "borg_configs.md file not found." | tee -a $LOGFILE
    fi
}

# Function to check the repository size
monitor_size() {
    check_borg_installed
    if [ -z "$BORG_REPO" ]; then
        error_exit "BORG_REPO is not set. Exiting."
    fi
    echo "Calculating the size of the repository:" | tee -a $LOGFILE
    du -sh "$BORG_REPO" | tee -a $LOGFILE
}

# Function to set up notifications
setup_notifications() {
    read -p "Enter your email address for notifications: " email
    if [ -z "$email" ]; then
        error_exit "No email provided. Exiting."
    fi
    echo "Setting up notifications for backup failures..." | tee -a $LOGFILE
    # Add mail sending logic to the backup script
    echo "if [ \${global_exit} -ne 0 ]; then" >> ~/borgbackup/backup_script.sh
    echo "    echo 'BorgBackup failed on \$(hostname)' | mail -s 'BorgBackup Failure' $email" >> ~/borgbackup/backup_script.sh
    echo "fi" >> ~/borgbackup/backup_script.sh
    echo "Notification setup completed." | tee -a $LOGFILE
}

# Function to run multiple checks
run_all_checks() {
    check_borg_installed
    check_logs
    verify_archives
    check_crontab
    review_configs
    monitor_size
}

# Function to prompt for checks
prompt_check_type() {
    echo "What would you like to check?"
    echo "1. Check BorgBackup logs"
    echo "2. Verify backup archives"
    echo "3. Test restore"
    echo "4. Check crontab entries"
    echo "5. Review borg_configs.md"
    echo "6. Check the repository size"
    echo "7. Set up notifications"
    echo "8. Run all checks"
    read -p "Please enter your choice (1 - 8): " choice

    case $choice in
        1)
            check_logs
            ;;
        2)
            verify_archives
            ;;
        3)
            test_restore
            ;;
        4)
            check_crontab
            ;;
        5)
            review_configs
            ;;
        6)
            monitor_size
            ;;
        7)
            setup_notifications
            ;;
        8)
            run_all_checks
            ;;
        *)
            error_exit "Invalid choice. Exiting."
            ;;
    esac
}

# Check if an argument was provided
if [ $# -eq 0 ]; then
    prompt_check_type
else
    case $1 in
        logs)
            check_logs
            ;;
        archives)
            verify_archives
            ;;
        restore)
            test_restore
            ;;
        crontab)
            check_crontab
            ;;
        configs)
            review_configs
            ;;
        size)
            monitor_size
            ;;
        notifications)
            setup_notifications
            ;;
        all)
            run_all_checks
            ;;
        *)
            error_exit "Invalid argument. Exiting."
            ;;
    esac
fi
