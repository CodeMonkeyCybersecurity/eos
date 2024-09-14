#!/bin/bash

echo "updating apt"
sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove -y && sudo apt autoclean
echo "updated and upgraded apt"

sudo apt install gnome-core -y
echo "installed gnome-core"

sudo apt install gnome-remote-desktop -y
echo "installed gnome-remote-desktop"

sudo ufw allow 3389/tcp  # For RDP
sudo ufw enable && sudo ufw reload
echo "firewall configs adapted"

sudo systemctl enable gnome-remote-desktop.service
echo "gnome-remote-desktop.service"

echo "finis"
