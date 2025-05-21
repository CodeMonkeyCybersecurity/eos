#!/bin/bash

# Script to install XFCE Desktop on Ubuntu Server

echo "Starting XFCE and GNOME Keyring installation script..."

# Update package list and upgrade packages
echo "Updating debian..."
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

# Install GNOME Keyring for keychain functionality
echo "Installing GNOME Keyring for keychain management..."
sudo apt install -y gnome-keyring

# Update PAM configuration for GNOME Keyring auto-login
echo "Configuring GNOME Keyring for login keychain..."
echo "auth optional pam_gnome_keyring.so" | sudo tee -a /etc/pam.d/lightdm
echo "session optional pam_gnome_keyring.so auto_start" | sudo tee -a /etc/pam.d/lightdm

# Set the default target to graphical (graphical.target)
echo "Setting system default to graphical target..."
sudo systemctl set-default graphical.target

# Start the graphical interface
echo "Starting LightDM service..."
sudo systemctl restart lightdm

# Prompt for reboot
echo "XFCE and GNOME Keyring installation is complete. It is recommended to reboot the debian."
read -p "Would you like to reboot now? (y/n): " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
    sudo reboot
else
    echo "You can reboot later to apply the changes."
fi
