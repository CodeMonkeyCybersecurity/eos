#!/bin/bash
# install_tailscale.sh

echo "Do you want to install Tailscale on this machine? (y/n)"
read -r YES

if [[ "$YES" == "y" ]]; then
    echo "Installing Tailscale now."
    curl -fsSL https://tailscale.com/install.sh | sh
    echo "Tailscale has been installed."
else
    echo "Skipping Tailscale installation."
    exit 0
fi

echo "Do you want to start Tailscale now? (y/n)"
read -r YES

if [[ "$YES" == "y" ]]; then
    echo "Running 'sudo tailscale up'."
    sudo tailscale up
else
    echo "Skipping Tailscale startup."
    exit 0
fi
