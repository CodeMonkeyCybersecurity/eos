#!/bin/bash
# /softwareAndPackages/PostgreSQL/installPostgreSQL.sh
PROJECT_ROOT=$(realpath "$(dirname "$0")/../..") || { echo "Failed to source PROJECT_ROOT"; exit 1; }
source "$UTILITIES_DIR/start.sh" || { echo "Failed to source start.sh"; exit 1; }
apt install -y postgresql || { echo "Failed to install PostgreSQL"; exit 1; }
source "$UTILITIES_DIR/start.sh" || { echo "Failed to source stop.sh"; exit 1; }