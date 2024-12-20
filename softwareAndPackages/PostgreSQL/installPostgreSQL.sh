#!/bin/bash
# /softwareAndPackages/PostgreSQL/installPostgreSQL.sh
PROJECT_ROOT=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..") || { echo "Failed to source PROJECT_ROOT"; exit 1; }
echo "PROJECT_ROOT: $PROJECT_ROOT"
echo ""
UTILITIES_DIR="$PROJECT_ROOT/utilities" || { echo "Failed to source UTILITIES_DIR"; exit 1; }
echo "UTILITIES_DIR: $UTILITIES_DIR"
echo ""
source "$UTILITIES_DIR/start.sh" || { echo "Failed to source start.sh"; exit 1; }
apt install -y postgresql || { echo "Failed to install PostgreSQL"; exit 1; }
source "$UTILITIES_DIR/start.sh" || { echo "Failed to source stop.sh"; exit 1; }