#!/bin/bash

# Prompt the user to input the list of subdomains
echo "Please enter the subdomains (separated by spaces):"
read -a SUBDOMAINS

# Iterate over each subdomain
for DOMAIN in "${SUBDOMAINS[@]}"; do
    echo "Processing $DOMAIN..."

    ARCHIVE_PATH="/etc/letsencrypt/archive/$DOMAIN"
    LIVE_PATH="/etc/letsencrypt/live/$DOMAIN"

    # Check if the archive directory exists
    if [ -d "$ARCHIVE_PATH" ]; then
        # Create the live directory if it doesn't exist
        sudo mkdir -p "$LIVE_PATH"

        # Create symbolic links
        sudo ln -sf "$ARCHIVE_PATH/cert1.pem" "$LIVE_PATH/cert.pem"
        sudo ln -sf "$ARCHIVE_PATH/chain1.pem" "$LIVE_PATH/chain.pem"
        sudo ln -sf "$ARCHIVE_PATH/fullchain1.pem" "$LIVE_PATH/fullchain.pem"
        sudo ln -sf "$ARCHIVE_PATH/privkey1.pem" "$LIVE_PATH/privkey.pem"

        echo "Created symbolic links for $DOMAIN."
    else
        echo "Archive directory for $DOMAIN does not exist. Skipping..."
    fi
done

echo "Symbolic link creation process completed."
