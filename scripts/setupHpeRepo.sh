#!/bin/bash

# Variables
REPO_FILE="/etc/apt/sources.list.d/mcp.list"
KEYRING_DIR="/etc/apt/trusted.gpg.d"
HPE_KEYS=(
    "https://downloads.linux.hpe.com/SDR/hpPublicKey2048_key1.pub"
    "https://downloads.linux.hpe.com/SDR/hpePublicKey2048_key1.pub"
    "https://downloads.linux.hpe.com/SDR/hpePublicKey2048_key2.pub"
)

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." 1>&2
    exit 1
fi

# Download and import HPE keys
echo "Downloading and enrolling HPE public keys..."
for KEY_URL in "${HPE_KEYS[@]}"; do
    KEY_FILE=$(basename "$KEY_URL")
    wget -q "$KEY_URL" -O "$KEY_FILE"
    if [[ -f "$KEY_FILE" ]]; then
        gpg --no-default-keyring --keyring ./temp-keyring.gpg --import "$KEY_FILE"
        gpg --no-default-keyring --keyring ./temp-keyring.gpg --export | tee "$KEYRING_DIR/${KEY_FILE%.pub}.gpg" > /dev/null
        rm -f "$KEY_FILE"
    else
        echo "Failed to download $KEY_URL"
    fi
done

# Add the MCP repository
echo "Adding the MCP repository..."
cat <<EOF > "$REPO_FILE"
deb [signed-by=/etc/apt/trusted.gpg.d/hpePublicKey2048_key2.gpg] https://downloads.linux.hpe.com/SDR/repo/mcp jammy/current non-free
EOF

# Update the package index
echo "Updating package index..."
apt update

# Done
echo "HPE repository and keys added successfully."
