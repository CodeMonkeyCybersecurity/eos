#!/bin/bash
read -p "What is the old database name (the one you want to change)?: " OLD_DB_NAME
read -p "What is the new database name (what do you want to change it to)?: " NEW_DB_NAME
# Check for empty inputs
if [[ -z "$OLD_DB_NAME" || -z "$NEW_DB_NAME" ]]; then
    echo "Error: Both old and new database names are required."
    exit 1
fi
# Backup the database
BACKUP_FILE="${OLD_DB_NAME}_backup_$(date +%Y%m%d%H%M%S).sql"
echo "Backing up database '$OLD_DB_NAME' to '$BACKUP_FILE'..."
sudo -u postgres pg_dump "${OLD_DB_NAME}" > "$BACKUP_FILE"

if [[ $? -ne 0 ]]; then
    echo "Error: Failed to back up the database."
    exit 1
else
    echo "Backup completed successfully. Backup file: $BACKUP_FILE"
fi
# database renaming
echo "Renaming database from '$OLD_DB_NAME' to '$NEW_DB_NAME'..."
sudo -u postgres psql <<EOF
ALTER DATABASE "${OLD_DB_NAME}" RENAME TO "${NEW_DB_NAME}";
EOF
# Check if the rename was successful
if [[ $? -eq 0 ]]; then
    echo "Database renamed successfully."
else
    echo "Error: Failed to rename the database."
    exit 1
fi
# List all databases to confirm the changes
echo "Listing all databases..."
sudo -u postgres psql <<EOF
\l
EOF