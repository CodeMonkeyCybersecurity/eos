#!/bin/bash
# test.sh

sudo -u eos_user psql -d eos_db -c "\dn+"   # Check schema permissions
sudo -u eos_user psql -d eos_db -c "\dt"   # List tables in the eos_db
sudo ls -lah /var/log/cyberMonkey/
sudo cat /var/log/cyberMonkey/eos.log