#!/bin/bash

# Prompt the user for BORG_REPO, BORG_PASSPHRASE, and retention policies
read -p "Enter the BORG_REPO path (e.g., /mnt/borg-repo or ssh://username@host:/path/to/repo): " BORG_REPO
read -sp "Enter the BORG_PASSPHRASE (hidden input): " BORG_PASSPHRASE
echo
read -p "Enter the number of daily backups to keep: " KEEP_DAILY
read -p "Enter the number of weekly backups to keep: " KEEP_WEEKLY
read -p "Enter the number of monthly backups to keep: " KEEP_MONTHLY

# Ask for additional configuration details
read -p "Enter the daily backup time (e.g., 02:00 AM): " BACKUP_TIME_DAILY
read -p "Enter the weekly backup day and time (e.g., Sunday at 03:00 AM): " BACKUP_TIME_WEEKLY
read -p "Enter the monthly backup day and time (e.g., 1st of every month at 04:00 AM): " BACKUP_TIME_MONTHLY

read -p "Enter the hostname of the environment (e.g., $(hostname)): " HOSTNAME
OS_INFO=$(lsb_release -d | cut -f2)
read -p "Enter the important directories to backup (default: /etc, /home, /root, /var): " IMPORTANT_DIRS
IMPORTANT_DIRS=${IMPORTANT_DIRS:-/etc /home /root /var}

read -p "Enter any known issues or considerations (optional): " KNOWN_ISSUES
read -p "Enter contact information (e.g., Henry, henry@codemonkey.net.au): " CONTACT_INFO

# Create a configuration file in markdown format
CONFIG_FILE=~/borgbackup/borg_configs.md

cat << EOF > $CONFIG_FILE
# BorgBackup Configuration

## Repository Path
\`\`\`
BORG_REPO=${BORG_REPO}
\`\`\`

## Passphrase
\`\`\`
BORG_PASSPHRASE=${BORG_PASSPHRASE}
\`\`\`

## Retention Policy
- **Daily backups** to keep: ${KEEP_DAILY}
- **Weekly backups** to keep: ${KEEP_WEEKLY}
- **Monthly backups** to keep: ${KEEP_MONTHLY}

## Backup Schedule
- **Daily** at ${BACKUP_TIME_DAILY}
- **Weekly** on ${BACKUP_TIME_WEEKLY}
- **Monthly** on ${BACKUP_TIME_MONTHLY}

## Retention Strategy Justification
- **Daily backups**: Retain for ${KEEP_DAILY} days to ensure recent data is easily recoverable.
- **Weekly backups**: Retain for ${KEEP_WEEKLY} weeks to cover a typical work month.
- **Monthly backups**: Retain for ${KEEP_MONTHLY} months to allow for medium-term historical data recovery.

## Repository Information
- **Location**: ${BORG_REPO}
- **Remote Access**: ${BORG_REPO}
- **Encryption**: Enabled using \`repokey\`

## Environment Information
- **Hostname**: ${HOSTNAME}
- **Operating System**: ${OS_INFO}
- **Important Directories**: ${IMPORTANT_DIRS}

## Known Issues/Considerations
${KNOWN_ISSUES:-None}

## Contact Information
- **Maintainer**: ${CONTACT_INFO}

## Last Backup Status
- **Last Successful Backup**: N/A
- **Last Failure**: N/A

## Commands and Execution Notes
- **Backup Command**: \`borg create --verbose --filter AME --list --compression lz4 --exclude-caches --exclude 'home/*/.cache/*' --exclude 'var/tmp/*' ::'{hostname}-{now}' ${IMPORTANT_DIRS}\`
- **Execution Notes**: Ensure that all dependencies are installed before running the script.
EOF

echo "Configuration has been saved to $CONFIG_FILE"

# Export the variables so they can be used in the backup script
export BORG_REPO
export BORG_PASSPHRASE

# Add BorgBackup operations to crontab
(crontab -l 2>/dev/null; echo "0 ${BACKUP_TIME_DAILY%%:*} * * * ~/borgbackup/backup_script.sh > ~/borgbackup/backup.log 2>&1") | crontab -
(crontab -l 2>/dev/null; echo "0 ${BACKUP_TIME_WEEKLY%%:*} * * ${BACKUP_TIME_WEEKLY%% *} ~/borgbackup/backup_script.sh > ~/borgbackup/backup.log 2>&1") | crontab -
(crontab -l 2>/dev/null; echo "0 ${BACKUP_TIME_MONTHLY%%:*} ${BACKUP_TIME_MONTHLY%% *} * * ~/borgbackup/backup_script.sh > ~/borgbackup/backup.log 2>&1") | crontab -

echo "BorgBackup operations have been added to crontab."

# Log file for backup operation
LOGFILE=~/borgbackup/backup.log

# Function to log information
info() {
    printf "\n%s %s\n" "$(date)" "$*" | tee -a "$LOGFILE"
}

# Function to log and handle errors
error() {
    printf "\n%s %s\n" "$(date)" "$*" | tee -a "$LOGFILE" >&2
    exit 1
}

# Trap signals and log them
trap 'error "Backup interrupted"' INT TERM

# Backup function
backup() {
    info "Starting backup"
    borg create                         \
        --verbose                       \
        --filter AME                    \
        --list                          \
        --stats                         \
        --show-rc                       \
        --compression lz4               \
        --exclude-caches                \
        --exclude 'home/*/.cache/*'     \
        --exclude 'var/tmp/*'           \
                                        \
        ::'{hostname}-{now}'            \
        ${IMPORTANT_DIRS}
    return $?
}

# Pruning function
prune() {
    info "Pruning repository"
    borg prune                          \
        --list                          \
        --glob-archives '{hostname}-*'  \
        --show-rc                       \
        --keep-daily    ${KEEP_DAILY}   \
        --keep-weekly   ${KEEP_WEEKLY}  \
        --keep-monthly  ${KEEP_MONTHLY}
    return $?
}

# Compacting function
compact() {
    info "Compacting repository"
    borg compact
    return $?
}

# Main backup process
backup_exit=0
prune_exit=0
compact_exit=0

backup
backup_exit=$?

prune
prune_exit=$?

compact
compact_exit=$?

# Determine global exit status
global_exit=$(( backup_exit > prune_exit ? backup_exit : prune_exit ))
global_exit=$(( compact_exit > global_exit ? compact_exit : global_exit ))

# Log final status
if [ ${global_exit} -eq 0 ]; then
    info "Backup, Prune, and Compact finished successfully"
elif [ ${global_exit} -eq 1 ]; then
    info "Backup, Prune, and/or Compact finished with warnings"
else
    error "Backup, Prune, and/or Compact finished with errors"
fi

exit ${global_exit}