#!/bin/bash
# purgeAndReinstallSnapd.sh

sudo apt purge snapd
sudo rm -rf /var/cache/snapd /var/lib/snapd /snap /etc/systemd/system/snap* /var/snap

ls /snap
ls /var/snap
ls /var/lib/snapd

sudo apt update
sudo apt install snapd

sudo systemctl enable --now snapd
sudo systemctl start snapd