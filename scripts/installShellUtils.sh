#!/bin/bash

sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove && sudo apt autoclean \
sudo systemctl daemon-reload \

sudo apt install -y \
gh tree ncdu zfsutils-linux \
hub \
nmap \
htop iftop iotop nload glances\
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

sudo apt update && sudo systemctl daemon-reload
