# Function to check crontab entries
checkCrontab() {
    echo "Current crontab entries for the user:" | tee -a $LOGFILE
    crontab -l | tee -a $LOGFILE
}
