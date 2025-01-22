#!/bin/bash

echo "paste this line to the bottom of the following file: deb [arch=amd64 signed-by=/usr/share/keyrings/oracle-virtualbox-2016.gpg] https://download.virtualbox.org/virtualbox/debian jammy contrib
"

sudo nano /etc/apt/sources.list

wget -O- https://www.virtualbox.org/download/oracle_vbox_2016.asc | sudo gpg --yes --output /usr/share/keyrings/oracle-virtualbox-2016.gpg --dearmor

sudo apt update
sudo apt install virtualbox-7.1 -y