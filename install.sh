#!/bin/bash

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error

# Colors for pretty output
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

VERSION="v1.0.0"
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
curl -L -o eos "https://github.com/CodeMonkeyCybersecurity/eos/releases/download/$VERSION/eos-$OS-$ARCH"
chmod +x eos
sudo mv eos /usr/local/bin/
echo -e "${GREEN}Eos binary installed successfully.${RESET}"

# Configuration Variables
DB_NAME="eos_db"
DB_USER="postgres"
read -sp "Enter PostgreSQL password for user $DB_USER: " DB_PASSWORD
echo
DB_HOST="localhost"
DB_PORT="5432"

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

# Step 3: Setup PostgreSQL Database
function setup_database() {
    echo -e "${GREEN}Setting up PostgreSQL database...${RESET}"

    # Set environment variables for PostgreSQL
    export PGPASSWORD=$DB_PASSWORD

    # Create database if it doesn't exist
    if ! psql -U $DB_USER -h $DB_HOST -p $DB_PORT -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1; then
        if ! psql -U $DB_USER -h $DB_HOST -p $DB_PORT -c "CREATE DATABASE $DB_NAME"; then
            echo -e "${RED}Error: Failed to create the database.${RESET}"
            exit 1
        fi
    fi
    echo -e "${GREEN}Database '$DB_NAME' is ready.${RESET}"

    # Create required tables
    psql -U $DB_USER -h $DB_HOST -p $DB_PORT -d $DB_NAME <<EOF
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
    install_go_driver
    setup_database
    echo -e "${GREEN}Setup complete! You can now use the PostgreSQL-backed solution.${RESET}"
}

main