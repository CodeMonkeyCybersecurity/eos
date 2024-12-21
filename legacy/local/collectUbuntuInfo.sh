#!/bin/bash
# TODO: DO NOT USE STILL IN DEVELOPMENT

set -xe

../utils/checkSudo.sh

ps aux
users
ls -lah /tmp
apt list -i
snap list
df -h
lsblk
cat .bash_history
cat /etc/crontab
dmesg
ip a
crontab -l

set +x
