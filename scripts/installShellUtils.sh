#!/bin/bash

sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove && sudo apt autoclean

sudo apt install gh tree ncdu zfsutils-linux \
prometheus \
zx \
git \
fzf \
python3-fabric \
ansible \
nginx \
prettier \
borgbackup

sudo snap install powershell 

sudo snap refresh
