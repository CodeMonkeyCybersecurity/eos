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

EOS_VERSION="v1.0.0"
OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# Adjust ARCH for compatibility
if [ "$ARCH" == "x86_64" ]; then
  ARCH="amd64"
elif [ "$ARCH" == "arm"* ]; then
  ARCH="arm64"
else
    echo -e "${RED}Unsupported architecture: $ARCH${RESET}"
    exit 1
fi

# Download binary
echo -e "${GREEN}Downloading Eos binary...${RESET}"
curl -L -o eos "https://github.com/CodeMonkeyCybersecurity/eos/releases/download/$EOS_VERSION/eos-$OS-$ARCH"
chmod +x eos
sudo mv eos /usr/local/bin/
echo -e "${GREEN}Eos binary installed successfully.${RESET}"

setup_ssh_key() {
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

# Configuration Variables
DB_NAME="eos_db"
DB_USER="eos_user"
DB_HOST="localhost"
DB_PORT="5432"
PSQL_VERSION="16"

# Create a new system user for Eos with sudo permission limitation
function create_system_user() {
    echo -e "${GREEN}Creating system user 'eos_user'...${RESET}"

    # Check if the user already exists
    if id "eos_user" &>/dev/null; then
        echo -e "${GREEN}System user 'eos_user' already exists.${RESET}"
    else
        # Create the user with no login shell and no password
        sudo useradd -m -s /usr/sbin/nologin eos_user
        echo -e "${GREEN}System user 'eos_user' created successfully.${RESET}"
    fi

    # Add the user to the sudoers file with limitations
    SUDOERS_FILE="/etc/sudoers.d/eos_user"
    if [ ! -f "$SUDOERS_FILE" ]; then
        echo -e "${GREEN}Adding 'eos_user' to the sudoers file with limitations...${RESET}"
        echo "ALL ALL=(eos_user) NOPASSWD: /usr/local/bin/eos" | sudo tee "$SUDOERS_FILE" > /dev/null
        sudo chmod 440 "$SUDOERS_FILE"
        echo -e "${GREEN}'eos_user' added to the sudoers file with limited permissions.${RESET}"
    else
        echo -e "${GREEN}'eos_user' is already in the sudoers file.${RESET}"
    fi
}

# Temporarily change permissions for pg_hba.conf to allow script modification
function modify_pg_hba_conf() {
    local PG_HBA_CONF="/etc/postgresql/16/main/pg_hba.conf"

    echo -e "${GREEN}Updating permissions for pg_hba.conf...${RESET}"
    sudo chmod 644 "$PG_HBA_CONF" # Allow read and write access to others during script execution

    # Call function to configure peer authentication
    configure_peer_authentication

    echo -e "${GREEN}Reverting permissions for pg_hba.conf...${RESET}"
    sudo chmod 640 "$PG_HBA_CONF" # Restore restricted access
}

# Configure peer authentication for eos_user
function configure_peer_authentication() {
    local PG_HBA_CONF="/etc/postgresql/16/main/pg_hba.conf"
    local PEER_AUTH_ENTRY="local   all             eos_user                                peer"

    if ! grep -qF "$PEER_AUTH_ENTRY" "$PG_HBA_CONF"; then
        echo -e "${GREEN}Adding peer authentication for 'eos_user' to pg_hba.conf...${RESET}"
        echo "$PEER_AUTH_ENTRY" | sudo tee -a "$PG_HBA_CONF" > /dev/null
        echo -e "${GREEN}Peer authentication entry added.${RESET}"
    else
        echo -e "${GREEN}Peer authentication for 'eos_user' is already configured.${RESET}"
    fi

    echo -e "${GREEN}Restarting PostgreSQL to apply changes...${RESET}"
    sudo systemctl restart postgresql
}

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

# Step 2: Install Go PostgreSQL Driver
function install_go_driver() {
    echo -e "${GREEN}Installing Go PostgreSQL driver...${RESET}"
    go get github.com/lib/pq
    echo -e "${GREEN}Go PostgreSQL driver installed successfully.${RESET}"
}

# Add a new PostgreSQL user for the Eos app
function create_eos_user() {
    echo -e "${GREEN}Creating 'eos_user' in PostgreSQL...${RESET}"

    # Check if the user already exists
    if psql -U postgres -tc "SELECT 1 FROM pg_roles WHERE rolname = 'eos_user'" | grep -q 1; then
        echo -e "${GREEN}'eos_user' already exists.${RESET}"
    else
        # Create the user
        if ! psql -U postgres -c "CREATE ROLE eos_user WITH LOGIN CREATEDB PASSWORD 'eos_password';"; then
            echo -e "${RED}Error: Failed to create 'eos_user'.${RESET}"
            exit 1
        fi
        echo -e "${GREEN}'eos_user' created successfully.${RESET}"
    fi
}

# Step 3: Setup PostgreSQL Database peer authentication
function ensure_peer_authentication() {
    echo -e "${GREEN}Ensuring peer authentication is configured...${RESET}"

    # Path to pg_hba.conf (adjust for your PostgreSQL version and installation)
    PG_HBA_CONF="/etc/postgresql/${PSQL_VERSION}/main/pg_hba.conf"
    PEER_AUTH_ENTRY="local   all             postgres                                peer"

    # Check if pg_hba.conf exists
    if [ ! -f "$PG_HBA_CONF" ]; then
        echo -e "${RED}Error: pg_hba.conf not found at $PG_HBA_CONF.${RESET}"
        exit 1
    fi

# Step 3: Setup PostgreSQL Database
function setup_database() {
    echo -e "${GREEN}Setting up PostgreSQL database...${RESET}"

    # Define the pg_hba.conf path and peer authentication entry for 'eos_user'
    PG_HBA_CONF="/etc/postgresql/14/main/pg_hba.conf" # Adjust for your PostgreSQL version
    PEER_AUTH_ENTRY="local   all             eos_user                                peer"

    # Check and add peer authentication if missing
    if ! grep -qF "$PEER_AUTH_ENTRY" "$PG_HBA_CONF"; then
        echo -e "${GREEN}Adding peer authentication for 'eos_user' to pg_hba.conf...${RESET}"
        echo "$PEER_AUTH_ENTRY" | sudo tee -a "$PG_HBA_CONF" > /dev/null
    else
        echo -e "${GREEN}Peer authentication for 'eos_user' is already configured.${RESET}"
    fi

    # Restart PostgreSQL to apply changes
    echo -e "${GREEN}Restarting PostgreSQL to apply changes...${RESET}"
    sudo systemctl restart postgresql

    # Create 'eos_user' if it doesn't exist
    if ! psql -U postgres -tc "SELECT 1 FROM pg_roles WHERE rolname = 'eos_user'" | grep -q 1; then
        echo -e "${GREEN}Creating PostgreSQL user 'eos_user'...${RESET}"
        psql -U postgres -c "CREATE ROLE eos_user WITH LOGIN CREATEDB;"
    else
        echo -e "${GREEN}PostgreSQL user 'eos_user' already exists.${RESET}"
    fi

    # Create the 'eos_db' database if it doesn't exist
    if ! psql -U postgres -tc "SELECT 1 FROM pg_database WHERE datname = 'eos_db'" | grep -q 1; then
        echo -e "${GREEN}Creating database 'eos_db' owned by 'eos_user'...${RESET}"
        psql -U postgres -c "CREATE DATABASE eos_db OWNER eos_user;"
    else
        echo -e "${GREEN}Database 'eos_db' already exists.${RESET}"
    fi

    echo -e "${GREEN}PostgreSQL database and user setup complete.${RESET}"
}

    echo -e "${GREEN}Peer authentication configured successfully.${RESET}"
}

    # Create database if it doesn't exist
    if ! psql -U $DB_USER -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1; then
        if ! psql -U $DB_USER -c "CREATE DATABASE $DB_NAME"; then
            echo -e "${RED}Error: Failed to create the database.${RESET}"
            exit 1
        fi
    fi
    echo -e "${GREEN}Database '$DB_NAME' is ready.${RESET}"

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

# Step 4: Run Setup
function main() {
    check_prerequisites
    setup_ssh_key
    ensure_peer_authentication
    install_go_driver
    create_eos_user
    setup_database
    export_script_variables
    echo -e "${GREEN}Setup complete! You can now use eos with `eos [command] [focus] [--modifier]`.${RESET}"
}

main