#!/bin/bash
# /softwareAndPackages/PostgreSQL/installPostgreSQL.sh
SCRIPT_DIR=$(dirname "$(realpath "$0")")
source "$SCRIPT_DIR/../../utilities/start.sh" || { echo "Failed to source start.sh"; exit 1; }
apt install -y postgresql || { echo "Failed to install PostgreSQL"; exit 1; }
source "$SCRIPT_DIR/../../utilities/stop.sh" || { echo "Failed to source stop.sh"; exit 1; }
