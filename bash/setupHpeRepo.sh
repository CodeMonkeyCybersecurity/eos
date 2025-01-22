#!/bin/bash

# Variables
REPO_FILE="/etc/apt/sources.list.d/mcp.list"
KEYRING_DIR="/etc/apt/trusted.gpg.d"
DIST=$(lsb_release -sc)
REPO_URL="https://downloads.linux.hpe.com/SDR/repo/mcp"
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
deb [signed-by=/etc/apt/trusted.gpg.d/hpePublicKey2048_key2.gpg] $REPO_URL $DIST/current non-free
EOF

#confirm keys added correctly
echo "listing gpg.d keys to confirm they're added correctly..."
ls "$KEYRING_DIR"

# Update the package index
echo "Updating package index..."
if ! apt update; then
    echo "Failed to update package index. Exiting."
    exit 1
fi

# Array of HPE packages
HPE_PACKAGES=(
    "hp-health"         # HPE System Health Application and Command line Utilities (Gen9 and earlier)
    "hponcfg"           # HPE RILOE II/iLO online configuration utility
    "amsd"              # HPE Agentless Management Service (Gen10 and newer)
    "hp-ams"            # HPE Agentless Management Service (Gen9 and earlier)
    "hp-snmp-agents"    # Insight Management SNMP Agents for HPE ProLiant Systems (Gen9 and earlier)
    "hpsmh"             # HPE System Management Homepage (Gen9 and earlier)
    "hp-smh-templates"  # HPE System Management Homepage Templates (Gen9 and earlier)
    "ssacli"            # HPE Command Line Smart Storage Administration Utility
    "ssaducli"          # HPE Command Line Smart Storage Administration Diagnostics
    "ssa"               # HPE Array Smart Storage Administration Service
    "storcli"           # MegaRAID command line interface
)


# Install each package in the array
echo "Installing HPE packages..."
for PACKAGE in "${HPE_PACKAGES[@]}"; do
    echo "Installing $PACKAGE..."
    if ! apt install -y "$PACKAGE"; then
        echo "Failed to install $PACKAGE. Continuing with the next package."
    fi
done

echo "All packages installed successfully."

echo "Finis"
