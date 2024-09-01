#!/bin/bash

sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove && sudo apt autoclean \

sudo apt install -y \
gh tree ncdu zfsutils-linux \
hub \
nmap \
htop \
prometheus \
zx \
git \
fzf \
python3-fabric python3-pip\
ansible \
nginx \
borgbackup \
npm && \

npm install -g zx && \

sudo snap install powershell  --classic && \

sudo snap refresh
