#!/bin/bash

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." 1>&2
    exit 1
fi

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
apt update && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y
checkCommand "System update and cleanup"

echo "Installing required packages..."
apt install -y --fix-missing \
nfs-kernel-server nfs-common \
mailutils lm-sensors \
gh tree ncdu ssh nmap wireguard \
htop iftop iotop nload glances \
prometheus git fzf python3-pip \
nginx borgbackup etckeeper ufw
checkCommand "Package installation"

# Install npm function
function installNpmZx() {
    if yesNoPrompt "Do you want to install zx for scripting?"; then
        echo "Proceeding with zx installation..."
        if ! command -v npm &>/dev/null; then
            echo "npm not found. Installing npm..."
            sudo apt install -y npm
            checkCommand "npm installation"
        fi
        sudo npm install -g zx
        checkCommand "zx installation"
    else
        echo "Installation of zx canceled."
    fi
}


# Install PowerShell function
function installPwsh() {
    if yesNoPrompt "Do you want to install PowerShell for scripting?"; then
        echo "Proceeding with PowerShell installation..."
        snap install powershell --classic && snap refresh
        checkCommand "PowerShell installation"
    else
        echo "PowerShell installation canceled."
    fi
}

# Setup UFW function
function setupUfw() {
    if ! command -v ufw &>/dev/null; then
        echo "Installing UFW..."
        apt install -y ufw
        checkCommand "UFW installation"
    else
        echo "UFW is already installed."
    fi

    echo "Configuring UFW..."
    sufw default deny incoming
    ufw default allow outgoing

    services=("ssh" "http" "https")
    for service in "${services[@]}"; do 
        if yesNoPrompt "Do you want to allow $service?"; then
            echo "Allowing $service..."
            ufw allow "$service"
            checkCommand "Allow $service"
        else
            echo "$service not allowed."
        fi
    done

    ufw enable
    checkCommand "UFW enable"
    echo "UFW setup complete."
}

# Install Tailscale function
function installTailscale() {
    if ! command -v curl &>/dev/null; then
        echo "curl not found. Installing curl..."
        apt install -y curl
        checkCommand "curl installation"
    fi

    if yesNoPrompt "Do you want to install and start Tailscale for VPN mesh networking?"; then
        echo "Installing and starting Tailscale..."
        curl -fsSL https://tailscale.com/install.sh | sh
        checkCommand "Tailscale installation script"
        apt install -y tailscale
        checkCommand "Tailscale package installation"
        tailscale up
        checkCommand "Tailscale startup"
    else
        echo "Tailscale not installed."
    fi
}

# Run functions
installNpmZx
installPwsh
setupUfw
installTailscale

echo "System update, package installation, and UFW setup complete."
