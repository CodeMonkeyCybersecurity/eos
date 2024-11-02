#!/bin/bash

# Script to install XFCE Desktop on Ubuntu Server

echo "Starting XFCE installation script..."

# Update package list and upgrade packages
echo "Updating system..."
sudo apt update && sudo apt upgrade -y

# Install XFCE4 and additional goodies
echo "Installing XFCE and additional packages..."
sudo apt install -y xfce4 xfce4-goodies

# Install LightDM as the display manager
echo "Installing LightDM display manager..."
sudo apt install -y lightdm

# Configure LightDM as the default display manager
echo "Configuring LightDM as the default display manager..."
sudo debconf-set-selections <<< "lightdm shared/default-x-display-manager select lightdm"
sudo dpkg-reconfigure -f noninteractive lightdm

# Install additional utilities
echo "Installing additional utilities..."
sudo apt install -y xfce4-terminal thunar-archive-plugin xfce4-clipman-plugin network-manager-gnome

# Set the default target to graphical (graphical.target)
echo "Setting system default to graphical target..."
sudo systemctl set-default graphical.target

# Start the graphical interface
echo "Starting LightDM service..."
sudo systemctl restart lightdm

# Prompt for reboot
echo "XFCE installation is complete. It is recommended to reboot the system."
read -p "Would you like to reboot now? (y/n): " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    sudo reboot
else
    echo "You can reboot later to apply the changes."
fi
