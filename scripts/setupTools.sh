#!/bin/bash

sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove && sudo apt autoclean \
sudo systemctl daemon-reload \

sudo apt install -y \
nfs-kernel-server nfs-common \
mailutils lm-sensors \
gh tree ncdu ceph ceph-deploy btrfs-progs \
openssh \ 
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
ufw \ 

npm && \

npm install -g zx && \

sudo snap install powershell  --classic && \

sudo snap refresh

sudo apt update && sudo systemctl daemon-reload
sudo ufw allow openssh 
sudo ufw allow http
sudo ufw allow https
sudo systemctl enable ufw && sudo systemctl start ufw
sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove && sudo apt autoclean \


