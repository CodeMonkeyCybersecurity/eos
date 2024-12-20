#!/bin/bash
# /softwareAndPackages/PostgreSQL/installPostgreSQL.sh
PROJECT_ROOT=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..") || { echo "Failed to source PROJECT_ROOT"; exit 1; }
echo "PROJECT_ROOT: $PROJECT_ROOT"
echo ""
UTILITIES_DIR="$PROJECT_ROOT/utilities"
echo "UTILITIES_DIR: $UTILITIES_DIR"
echo ""
source "$UTILITIES_DIR/apt.sh"
source "$UTILITIES_DIR/start.sh" || { echo "Failed to source start.sh"; exit 1; }
apt install -y postgresql || { echo "Failed to install PostgreSQL"; exit 1; }
postgresql --version
systemctl enable postgresql
systemctl start postgresql
echo "PostgreSQL service is started and enabled"
psql --version

# Set up configuration
read -p "Enter the PostgreSQL version printed above, ignoring any digits after the decimal point. (e.g., 16.6 becomes 16, 15.1 becomes 15, etc.): " PSQL_VERSION
PSQL_CONFIG_DIR="/etc/postgresql/${PSQL_VERSION}/main"
if [ ! -d "$PSQL_CONFIG_DIR" ]; then
    echo "Configuration directory not found: $PSQL_CONFIG_DIR"
    exit 1
fi

# back up postgresql.conf
sudo cp $PSQL_CONFIG_DIR/postgresql.conf $PSQL_CONFIG_DIR/postgresql.conf.bak

echo "Set Up a Superuser Password"
read -n 1 -s -r -p "Press any key to continue..."
echo ""
sudo -u postgres psql
\password postgres

# TODO figure this out
# Automate configuration edits
#sed -i "s/peer/scram-sha-256/" "$PSQL_CONFIG_DIR/pg_hba.conf"
#sed -i "s/md5/scram-sha-256/" "$PSQL_CONFIG_DIR/pg_hba.conf"
psql -U postgres
psql -U postgres -c "SHOW listen_addresses;"
psql -U postgres -c "SHOW ssl;"
psql -U postgres -c "\du"
psql -U postgres -c "SELECT usename, client_addr, application_name FROM pg_stat_activity;"

systemctl restart postgresql
source "$UTILITIES_DIR/stop.sh" || { echo "Failed to source stop.sh"; exit 1; }
