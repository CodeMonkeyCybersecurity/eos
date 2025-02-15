#!/bin/bash

set +xe

echo ""
echo "add oracle GPG key"
wget -qO- https://www.virtualbox.org/download/oracle_vbox_2016.asc | sudo tee /etc/apt/trusted.gpg.d/oracle-virtualbox.asc

echo ""
echo "adding VirtualBox repositor"
echo "deb [arch=amd64] https://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list


echo ""
echo " Install the latest VirtualBox"
sudo apt update
sudo apt install virtualbox-7.1 -y

echo ""
echo "finis"

set -xe
