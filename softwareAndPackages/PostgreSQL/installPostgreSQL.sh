#!/bin/bash
# /softwareAndPackages/PostgreSQL/installPostgreSQL.sh
source ../../utilities/start.sh || { echo "Failed to source start.sh"; exit 1; }
apt install -y postgresql || { echo "Failed to install PostgreSQL"; exit 1; }
source ../../utilities/stop.sh || { echo "Failed to source stop.sh"; exit 1; }