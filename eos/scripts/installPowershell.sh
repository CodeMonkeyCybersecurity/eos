#!/bin/bash

# Update the list of packages
sudo apt-get update

# Install pre-requisite packages.
sudo apt install -y snap snapd 

sudo snap instal powershell

echo "done"
