#!/bin/bash

sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove && sudo apt autoclean \
sudo systemctl daemon-reload \

sudo apt install -y \
nfs-kernel-server nfs-common \
mailutils lm-sensors \
gh tree ncdu ssh nmap wireguard \
htop iftop iotop nload glances \
prometheus zx git fzf python3-pip \
nginx borgbackup etckeeper ufw npm && \

npm install -g zx && \

sudo snap install powershell  --classic && \

sudo snap refresh

sudo apt update && sudo systemctl daemon-reload
sudo ufw allow openssh
sudo ufw allow http
sudo ufw allow https
sudo systemctl enable ufw && sudo systemctl start ufw
sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove && sudo apt autoclean \


