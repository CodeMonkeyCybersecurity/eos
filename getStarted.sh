#!/bin/bash

echo "Starting system update and cleanup..."
sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y

echo "Installing required packages..."
sudo apt install -y \
nfs-kernel-server nfs-common \
mailutils lm-sensors \
gh tree ncdu ssh nmap wireguard \
htop iftop iotop nload glances \
prometheus zx git fzf python3-pip \
nginx borgbackup etckeeper ufw

# Install npm function
function installNpm() {
    read -p "Do you want to install zx for scripting? (y/n): " choice
    case "$choice" in 
      y|Y )
        echo "Proceeding with npm installation..."
        sudo apt install -y npm && sudo npm install -g zx
        ;;
      n|N )
        echo "Installation of zx canceled."
        ;;
      * )
        echo "Invalid input, please enter y or n."
        installNpm
        ;;
    esac
}

# Install PowerShell function
function installPwsh() {
    read -p "Do you want to install PowerShell for scripting? (y/n): " choice
    case "$choice" in 
      y|Y )
        echo "Proceeding with PowerShell installation..."
        sudo snap install powershell --classic &&
        sudo snap refresh
        ;;
      n|N )
        echo "PowerShell installation canceled."
        ;;
      * )
        echo "Invalid input, please enter y or n."
        installPwsh
        ;;
    esac
}

# Setup UFW function
function setupUfw() {
    read -p "Do you want to set up UFW (Uncomplicated Firewall)? (y/n): " ufw_choice
    case "$ufw_choice" in 
      y|Y )
        echo "Setting up UFW..."
        sudo apt install -y ufw
        sudo ufw default deny incoming
        sudo ufw default allow outgoing

        services=("ssh" "http" "https" "sftp")

        for service in "${services[@]}"; do 
          read -p "Do you want to allow $service? (y/n): " service_choice
          case "$service_choice" in 
            y|Y )
              echo "Allowing $service..."
              sudo ufw allow "$service"
              ;;
            n|N )
              echo "$service not allowed."
              ;;
            * )
              echo "Invalid input for $service. Please enter y or n."
              ;;
          esac
        done

        sudo ufw enable
        echo "UFW setup complete."
        ;;
      
      n|N )
        echo "UFW setup canceled."
        ;;
      
      * )
        echo "Invalid input, please enter y or n."
        setupUfw
        ;;
    esac
}

# Run functions
installNpm
installPwsh
setupUfw

echo "System update, package installation, and UFW setup complete."
