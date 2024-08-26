#!/bin/sh

# Prompt the user for BORG_REPO and BORG_PASSPHRASE
read -p "Enter the BORG_REPO (e.g., ssh://username@example.com:2022/~/backup/main): " BORG_REPO
export BORG_REPO

read -s -p "Enter the BORG_PASSPHRASE (input will be hidden): " BORG_PASSPHRASE
export BORG_PASSPHRASE

echo # Move to a new line after the passphrase input

# Prompt the user for retention policy values
read -p "Enter the number of daily backups to keep (default 7): " keep_daily
keep_daily=${keep_daily:-7}

read -p "Enter the number of weekly backups to keep (default 4): " keep_weekly
keep_weekly=${keep_weekly:-4}

read -p "Enter the number of monthly backups to keep (default 6): " keep_monthly
keep_monthly=${keep_monthly:-6}

# Some helpers and error handling:
info() { printf "\n%s %s\n\n" "$(date)" "$*" >&2; }
trap 'echo $(date) Backup interrupted >&2; exit 2' INT TERM

info "Starting backup"

# Backup the most important directories into an archive named after
# the machine this script is currently running on:

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
    /etc                            \
    /home                           \
    /root                           \
    /var

backup_exit=$?

info "Pruning repository"

# Use the `prune` subcommand to maintain daily, weekly, and monthly archives
# according to the user's input:

borg prune                          \
    --list                          \
    --glob-archives '{hostname}-*'  \
    --show-rc                       \
    --keep-daily    "${keep_daily}" \
    --keep-weekly   "${keep_weekly}"\
    --keep-monthly  "${keep_monthly}"

prune_exit=$?

# Actually free repo disk space by compacting segments

info "Compacting repository"

borg compact

compact_exit=$?

# Use the highest exit code as the global exit code
global_exit=$(( backup_exit > prune_exit ? backup_exit : prune_exit ))
global_exit=$(( compact_exit > global_exit ? compact_exit : global_exit ))

if [ ${global_exit} -eq 0 ]; then
    info "Backup, Prune, and Compact finished successfully"
elif [ ${global_exit} -eq 1 ]; then
    info "Backup, Prune, and/or Compact finished with warnings"
else
    info "Backup, Prune, and/or Compact finished with errors"
fi

exit ${global_exit}
