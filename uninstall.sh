#!/bin/bash

set -e

# Define paths
Eos_BIN="/usr/local/bin/eos"
Eos_DIR="/opt/eos"
Eos_CONFIG="/etc/eos"
Eos_LOG="/var/log/eos"
Eos_STATE="/var/lib/eos"
Eos_RUN="/var/run/eos"
Eos_SYSTEMD="/etc/systemd/system"
VAULT_SYSTEMD="${Eos_SYSTEMD}/vault.service"
VAULT_AGENT_SYSTEMD="${Eos_SYSTEMD}/vault-agent-eos.service"
Eos_USER="eos"
Eos_GROUP="eos"
SUDOERS_FILE="/etc/sudoers.d/eos"

echo "🛑 Stopping and disabling Eos services..."
sudo systemctl stop eos.service || true
sudo systemctl disable eos.service || true
sudo systemctl stop vault.service || true
sudo systemctl disable vault.service || true
sudo systemctl stop vault-agent-eos.service || true
sudo systemctl disable vault-agent-eos.service || true

echo "🧹 Removing binaries and directories..."
sudo rm -f "${Eos_BIN}"
sudo rm -rf "${Eos_DIR}"
sudo rm -rf "${Eos_CONFIG}"
sudo rm -rf "${Eos_LOG}"
sudo rm -rf "${Eos_STATE}"
sudo rm -rf "${Eos_RUN}"

echo "🗑 Removing systemd service files..."
sudo rm -f "${Eos_SYSTEMD}/eos.service"
sudo rm -f "${VAULT_SYSTEMD}"
sudo rm -f "${VAULT_AGENT_SYSTEMD}"
sudo systemctl daemon-reload

echo "👥 Removing eos user, group, and sudoers..."
if id "${Eos_USER}" &>/dev/null; then
    sudo userdel "${Eos_USER}"
fi
if getent group "${Eos_GROUP}" &>/dev/null; then
    sudo groupdel "${Eos_GROUP}"
fi
sudo rm -f "${SUDOERS_FILE}"

echo "✅ Eos has been purged from the system."