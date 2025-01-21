#!/bin/bash
echo "starting"
sudo apt install -y xrdp
sudo systemctl start xrdp
sudo systemctl enable xrdp
echo "done"
