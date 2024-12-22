#!/bin/bash

# Function to check if the script is being run as root
checkSudo() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "\033[31m✘ This script must be run as sudo. Please use sudo <your command>.\033[0m"
        exit 1
    else
        echo -e "\033[32m✔ Running with sudo.\033[0m"
    fi
}
# Code to execute when the script is run directly
checkSudo
set -ex  # Exit immediately if a command exits with a non-zero status

function export_script_variables() {
    local output_file="script_vars.env"
    echo "Exporting script variables to $output_file..."
    
    # Empty (or create) the output file
    : > "$output_file"
    
    # Iterate over all variables known to the shell
    for var in $(compgen -v); do
        # Skip some built-in or special Bash variables
        if [[ ! "$var" =~ ^(BASH_|EUID|UID|PPID|LINENO|FUNCNAME|GROUPS|_|PWD|OLDPWD)$ ]]; then
            # Write each variable in the form: export VAR="value"
            echo "export $var=\"${!var}\"" >> "$output_file"
        fi
    done
    chmod 600 script_vars.env
    echo "Done. You can 'source $output_file' to re-import these variables."
}
export_script_variables

# Set up timestamps and log file paths
TIMESTAMP="$(date +"%Y-%m-%d_%H-%M-%S")"
USER_HOSTNAME_STAMP="$(hostname)_$(whoami)"
STAMP="${TIMESTAMP}_${USER_HOSTNAME_STAMP}"
CYBERMONKEY_LOG_DIR="${CYBERMONKEY_LOG_DIR:-/var/log/cyberMonkey}"
mkdir -p "$CYBERMONKEY_LOG_DIR"
EOS_LOG_FILE="${CYBERMONKEY_LOG_DIR}/eos.log"

# Colors for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

# Redirect all output (stdout and stderr) to the log file
exec > >(tee -a "$EOS_LOG_FILE") 2>&1

# Log script start with timestamp
echo "${RED} Script started at $STAMP ${RESET}"

# Variables for binary download
SYSTEM_USER="eos_user"
EOS_VERSION="v1.0.0"
OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# Download binary
echo -e "${GREEN}Downloading Eos binary...${RESET}"
curl -L -o eos "https://github.com/CodeMonkeyCybersecurity/eos/releases/download/$EOS_VERSION/eos-$OS-$ARCH"
chmod +x eos
sudo mv eos /usr/local/bin/
echo -e "${GREEN}Eos binary installed successfully.${RESET}"

# Configuration Variables
DB_NAME="eos_db"
DB_USER="$SYSTEM_USER"
DB_HOST="localhost"
DB_PORT="5432"
PSQL_VERSION="16"

# Create a new system user for Eos with sudo permission limitation
function create_eos_system_user() {
    echo -e "${GREEN}Creating system user ${SYSTEM_USER}...${RESET}"
    if id "$SYSTEM_USER" &>/dev/null; then
        echo -e "${GREEN}System user ${SYSTEM_USER} already exists.${RESET}"
    else
        sudo useradd -m -s /usr/sbin/nologin -p '!' ${SYSTEM_USER}
        echo -e "${GREEN}System user ${SYSTEM_USER} created successfully.${RESET}"
    fi

    # Add user to sudoers if needed
    SUDOERS_FILE="/etc/sudoers.d/${SYSTEM_USER}"
    if [ ! -f "$SUDOERS_FILE" ]; then
        echo -e "${GREEN}Adding ${SYSTEM_USER} to the sudoers file with limitations...${RESET}"
        echo "ALL ALL=(${SYSTEM_USER}) NOPASSWD: /usr/local/bin/eos" | sudo tee "$SUDOERS_FILE" > /dev/null
        sudo chmod 440 "$SUDOERS_FILE"
        echo -e "${GREEN}${SYSTEM_USER} added to the sudoers file with limited permissions.${RESET}"
    else
        echo -e "${GREEN}${SYSTEM_USER} is already in the sudoers file.${RESET}"
    fi
}
create_eos_system_user

function setup_ssh_key() {
    echo -e "${GREEN}Setting up SSH key-based authentication...${RESET}"

    SSH_KEY_DIR="/home/$SYSTEM_USER/.ssh"
    SSH_KEY_FILE="$SSH_KEY_DIR/id_ed25519"

    sudo -u "$SYSTEM_USER" bash <<EOF
mkdir -p "$SSH_KEY_DIR"
chmod 700 "$SSH_KEY_DIR"
if [ ! -f "$SSH_KEY_FILE" ]; then
    ssh-keygen -t ed25519 -f "$SSH_KEY_FILE" -N ""
    chmod 600 "$SSH_KEY_FILE"
    chmod 644 "$SSH_KEY_FILE.pub"
else
    echo "SSH key already exists at $SSH_KEY_FILE"
fi
EOF
}

# Add a new PostgreSQL user for the Eos app
function create_eos_db_user() {
    echo -e "${GREEN}Creating $DB_USER in PostgreSQL...${RESET}"
    # **IMPORTANT**: any psql command as $DB_USER must be run as the system user too
    sudo -u postgres psql <<EOF
DO \$\$
BEGIN
    IF NOT EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}'
    ) THEN
        CREATE ROLE ${DB_USER} WITH LOGIN;
    END IF;
END
\$\$;
EOF
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully created or ensured existence of eos_user.${RESET}"
    else
        echo -e "${RED}Error: Failed to create or check eos_user.${RESET}"
        exit 1
    fi
}

# Configure peer authentication for eos_user
function configure_peer_authentication() {
    local PG_HBA_CONF="/etc/postgresql/${PSQL_VERSION}/main/pg_hba.conf"
    echo -e "${GREEN}Updating permissions for $PG_HBA_CONF...${RESET}"
    sudo chmod 644 "$PG_HBA_CONF"
    # Possibly update peer auth here
    sudo chmod 640 "$PG_HBA_CONF"
    local PEER_AUTH_ENTRY="local   all             ${SYSTEM_USER}                                peer"

    if ! grep -qF "$PEER_AUTH_ENTRY" "$PG_HBA_CONF"; then
        echo -e "${GREEN}Adding peer authentication for ${SYSTEM_USER} to pg_hba.conf...${RESET}"
        echo "$PEER_AUTH_ENTRY" | sudo tee -a "$PG_HBA_CONF" > /dev/null
        echo -e "${GREEN}Peer authentication entry added.${RESET}"
    else
        echo -e "${GREEN}Peer authentication for ${SYSTEM_USER} is already configured.${RESET}"
    fi

    echo -e "${GREEN}Restarting PostgreSQL to apply changes...${RESET}"
    sudo systemctl restart postgresql
}

function check_prerequisites() {
    echo -e "${GREEN}Checking prerequisites...${RESET}"
    if ! command -v go &>/dev/null; then
        echo -e "${RED}Error: Go is not installed. Please install Go first.${RESET}"
        exit 1
    fi

    if ! command -v psql &>/dev/null; then
        echo -e "${RED}Error: PostgreSQL is not installed. Please install PostgreSQL first.${RESET}"
        exit 1
    fi
}

# Step 2: Install Go PostgreSQL Driver
function install_go_driver() {
    echo -e "${GREEN}Installing Go PostgreSQL driver...${RESET}"
    go get github.com/lib/pq
    echo -e "${GREEN}Go PostgreSQL driver installed successfully.${RESET}"
}

# Step 3: Setup PostgreSQL Database peer authentication
function setup_eos_db() {
    sudo -u postgres psql <<EOF
    DO \$\$
    BEGIN
        IF NOT EXISTS (
            SELECT FROM pg_database WHERE datname = '${DB_NAME}'
        ) THEN
            CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};
        END IF;
    END
    \$\$;
EOF

    echo -e "${GREEN}PostgreSQL database setup complete.${RESET}"

    # Grant privileges to eos_user on the public schema
    sudo -u postgres psql -d "$DB_NAME" <<EOF
    GRANT ALL ON SCHEMA public TO ${DB_USER};
EOF

    # Create required tables
    sudo -u "$DB_USER" psql -d "$DB_NAME" <<EOF
CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    level VARCHAR(10),
    message TEXT
);

CREATE TABLE IF NOT EXISTS configurations (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT NOT NULL
);
EOF

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to create tables in eos_db.${RESET}"
        exit 1
    fi

    echo -e "${GREEN}Schema setup complete.${RESET}"
}

function main() {
    check_prerequisites
    setup_ssh_key
    create_eos_system_user
    create_eos_db_user
    configure_peer_authentication
    install_go_driver
    setup_eos_db
    echo -e "${GREEN}Setup complete! Use 'eos' as needed.${RESET}"
}
main
set +x