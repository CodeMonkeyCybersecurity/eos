#!/bin/bash

sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove && sudo apt autoclean \

sudo apt install gh tree ncdu zfsutils-linux \
prometheus \
zx \
git \
fzf \
python3-fabric \
ansible \
nginx \
borgbackup \
npm && \
npm install -g zx && \
sudo snap install powershell  --classic && \
sudo snap refresh
