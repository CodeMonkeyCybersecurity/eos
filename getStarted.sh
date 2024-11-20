#!/bin/bash

# Function to check the last command's exit status
function checkCommand() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed to execute. Exiting."
        exit 1
    fi
}

# Function to validate yes/no input
function yesNoPrompt() {
    while true; do
        read -p "$1 (y/n): " choice
        case "$choice" in
            y|Y ) return 0 ;;  # Yes
            n|N ) return 1 ;;  # No
            * ) echo "Invalid input. Please enter y or n." ;;
        esac
    done
}

echo "Starting system update and cleanup..."
sudo apt update && sudo apt dist-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y
checkCommand "System update and cleanup"

echo "Installing required packages..."
sudo apt install -y \
nfs-kernel-server nfs-common \
mailutils lm-sensors \
gh tree ncdu ssh nmap wireguard \
htop iftop iotop nload glances \
prometheus zx git fzf python3-pip \
nginx borgbackup etckeeper ufw
checkCommand "Package installation"

# Install npm function
function installNpm() {
    if yesNoPrompt "Do you want to install zx for scripting?"; then
        echo "Proceeding with npm installation..."
        sudo apt install -y npm && sudo npm install -g zx
        checkCommand "npm and zx installation"
    else
        echo "Installation of zx canceled."
    fi
}

# Install PowerShell function
function installPwsh() {
    if yesNoPrompt "Do you want to install PowerShell for scripting?"; then
        echo "Proceeding with PowerShell installation..."
        sudo snap install powershell --classic && sudo snap refresh
        checkCommand "PowerShell installation"
    else
        echo "PowerShell installation canceled."
    fi
}

# Setup UFW function
function setupUfw() {
    if ! command -v ufw &>/dev/null; then
        echo "Installing UFW..."
        sudo apt install -y ufw
        checkCommand "UFW installation"
    else
        echo "UFW is already installed."
    fi

    echo "Configuring UFW..."
    sudo ufw default deny incoming
    sudo ufw default allow outgoing

    services=("ssh" "http" "https")
    for service in "${services[@]}"; do 
        if yesNoPrompt "Do you want to allow $service?"; then
            echo "Allowing $service..."
            sudo ufw allow "$service"
            checkCommand "Allow $service"
        else
            echo "$service not allowed."
        fi
    done

    sudo ufw enable
    checkCommand "UFW enable"
    echo "UFW setup complete."
}

# Install Tailscale function
function installTailscale() {
    if ! command -v curl &>/dev/null; then
        echo "curl not found. Installing curl..."
        sudo apt install -y curl
        checkCommand "curl installation"
    fi

    if yesNoPrompt "Do you want to install and start Tailscale for VPN mesh networking?"; then
        echo "Installing and starting Tailscale..."
        curl -fsSL https://tailscale.com/install.sh | sh
        checkCommand "Tailscale installation script"
        sudo apt install -y tailscale
        checkCommand "Tailscale package installation"
        tailscale up
        checkCommand "Tailscale startup"
    else
        echo "Tailscale not installed."
    fi
}

# Run functions
installNpm
installPwsh
setupUfw
installTailscale

echo "System update, package installation, and UFW setup complete."
