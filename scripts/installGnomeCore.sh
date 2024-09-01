#!/bin/bash

echo "updating apt"
sudo apt update && sudo apt upgrade -y
echo "updated apt"

echo "installing gnome-core"
sudo apt install gnome-core -y
echo "installed gnome-core"

echo "done"
