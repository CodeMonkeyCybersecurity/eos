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
TIMESTAMP="$(date +"%Y-%m-%d_%H-%M-%S")"
USER_HOSTNAME_STAMP="$(hostname)_$(whoami)"
STAMP="${TIMESTAMP}_${USER_HOSTNAME_STAMP}"
mkdir -p "${CYBERMONKEY_LOG_DIR:-/var/log/cyberMonkey}"
EOS_LOG_FILE="${CYBERMONKEY_LOG_DIR}/eos.log"
# Redirect all output (stdout and stderr) to the log file
exec > >(tee -a "$EOS_LOG_FILE") 2>&1
# Log script start with timestamp
echo "\033[31m=== Script started at $STAMP ===\033[0m"

# Colors for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

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

    # Check if the user already exists
    if id "$SYSTEM_USER" &>/dev/null; then
        echo -e "${GREEN}System user ${SYSTEM_USER} already exists.${RESET}"
    else
        # Create the user with no login shell and no password
        sudo useradd -m -s /usr/sbin/nologin -p '!' ${SYSTEM_USER}
        echo -e "${GREEN}System user ${SYSTEM_USER} created successfully.${RESET}"
    fi

    # Add the user to the sudoers file with limitations
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
# Function to execute commands as eos_user
function run_as_eos_system_user() {
    local command="$1"
    echo -e "\033[32m✔ Running as ${SYSTEM_USER}: $command\033[0m"
    sudo -u ${SYSTEM_USER} bash -c "$command"
}
run_as_eos_system_user
function setup_ssh_key() {
    echo -e "${GREEN}Setting up SSH key-based authentication...${RESET}"

    SSH_KEY="$HOME/.ssh/id_ed25519"
    SSH_PUB_KEY="$HOME/.ssh/id_ed25519.pub"

    # Check if key already exists
    if [ -f "$SSH_KEY" ]; then
        echo -e "${GREEN}An SSH key already exists at $SSH_KEY.${RESET}"
    else
        echo -e "${GREEN}Generating a new SSH key pair...${RESET}"
        ssh-keygen -N "" -f "$SSH_KEY"
        echo -e "${GREEN}SSH key generated at $SSH_KEY.${RESET}"
    fi
}
setup_ssh_key
# Temporarily change permissions for pg_hba.conf to allow script modification
function modify_pg_hba_conf() {
    local PG_HBA_CONF="/etc/postgresql/${PSQL_VERSION}/main/pg_hba.conf"

    echo -e "${GREEN}Updating permissions for pg_hba.conf...${RESET}"
    sudo chmod 644 "$PG_HBA_CONF" # Allow read and write access to others during script execution

    echo -e "${GREEN}Reverting permissions for pg_hba.conf...${RESET}"
    sudo chmod 640 "$PG_HBA_CONF" # Restore restricted access
}
modify_pg_hba_conf
# Configure peer authentication for eos_user
function configure_peer_authentication() {
    local PG_HBA_CONF="/etc/postgresql/${PSQL_VERSION}/main/pg_hba.conf"
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
configure_peer_authentication
# Step 1: Check prerequisites
function check_prerequisites() {
    echo -e "${GREEN}Checking prerequisites...${RESET}"

    # Check for Go
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go is not installed. Please install Go first.${RESET}"
        exit 1
    fi

    # Check for PostgreSQL
    if ! command -v psql &> /dev/null; then
        echo -e "${RED}Error: PostgreSQL is not installed. Please install PostgreSQL first.${RESET}"
        exit 1
    fi
}
check_prerequisites
# Step 2: Install Go PostgreSQL Driver
function install_go_driver() {
    echo -e "${GREEN}Installing Go PostgreSQL driver...${RESET}"
    go get github.com/lib/pq
    echo -e "${GREEN}Go PostgreSQL driver installed successfully.${RESET}"
}
install_go_driver

# Add a new PostgreSQL user for the Eos app
function create_eos_db_user() {
    echo -e "${GREEN}Creating ${DB_USER} in PostgreSQL...${RESET}"

    # Check if the user already exists
    if psql -U ${DB_USER} -tc "SELECT 1 FROM pg_roles WHERE rolname = ${DB_USER}" | grep -q 1; then
        echo -e "${GREEN}${DB_USER} already exists.${RESET}"
    else
        # Create the user
        if ! psql -U ${DB_USER} -c "CREATE ROLE ${SYSTEM_USER} WITH LOGIN CREATEDB PASSWORD 'eos_password';"; then
            echo -e "${RED}Error: Failed to create ${DB_USER}.${RESET}"
            exit 1
        fi
        echo -e "${GREEN}${DB_USER} created successfully.${RESET}"
    fi
}
create_eos_db_user
# Step 3: Setup PostgreSQL Database peer authentication
function setup_eos_db() {
    # Create the 'eos_db' database if it doesn't exist
    if ! psql -U ${DB_USER} -tc "SELECT 1 FROM pg_database WHERE datname = 'eos_db'" | grep -q 1; then
        echo -e "${GREEN}Creating database 'eos_db' owned by ${DB_USER}...${RESET}"
        psql -U ${DB_USER} -c "CREATE DATABASE eos_db OWNER ${SYSTEM_USER};"
    else
        echo -e "${GREEN}Database 'eos_db' already exists.${RESET}"
    fi

    echo -e "${GREEN}PostgreSQL database and user setup complete.${RESET}"
}

    # Create required tables
    if ! psql -U $DB_USER -h $DB_HOST -p $DB_PORT -d $DB_NAME <<EOF
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
    then
        echo -e "${RED}Error: Failed to create schema.${RESET}"
        exit 1
    fi
    echo -e "${GREEN}Schema setup complete.${RESET}"

    # Validate database setup
    echo -e "${GREEN}Validating database setup...${RESET}"
    if ! psql -U $DB_USER -h $DB_HOST -p $DB_PORT -d $DB_NAME -c "\dt"; then
        echo -e "${RED}Database validation failed. Please check your setup.${RESET}"
        exit 1
    fi
    echo -e "${GREEN}Database validation successful.${RESET}"
}
setup_eos_db

# Step 4: Run Setup
function main() {
    echo -e "${GREEN}Setup complete! You can now use eos with `eos [command] [focus] [--modifier]`.${RESET}"
}

main