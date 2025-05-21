#!/bin/bash

set -e

# Define paths
EOS_BIN="/usr/local/bin/eos"
EOS_DIR="/opt/eos"
EOS_CONFIG="/etc/eos"
EOS_LOG="/var/log/eos"
EOS_STATE="/var/lib/eos"
EOS_RUN="/var/run/eos"
EOS_SYSTEMD="/etc/systemd/system"
VAULT_SYSTEMD="${EOS_SYSTEMD}/vault.service"
VAULT_AGENT_SYSTEMD="${EOS_SYSTEMD}/vault-agent-eos.service"
EOS_USER="eos"
EOS_GROUP="eos"
SUDOERS_FILE="/etc/sudoers.d/eos"

echo "🛑 Stopping and disabling EOS services..."
sudo systemctl stop eos.service || true
sudo systemctl disable eos.service || true
sudo systemctl stop vault.service || true
sudo systemctl disable vault.service || true
sudo systemctl stop vault-agent-eos.service || true
sudo systemctl disable vault-agent-eos.service || true

echo "🧹 Removing binaries and directories..."
sudo rm -f "${EOS_BIN}"
sudo rm -rf "${EOS_DIR}"
sudo rm -rf "${EOS_CONFIG}"
sudo rm -rf "${EOS_LOG}"
sudo rm -rf "${EOS_STATE}"
sudo rm -rf "${EOS_RUN}"

echo "🗑 Removing systemd service files..."
sudo rm -f "${EOS_SYSTEMD}/eos.service"
sudo rm -f "${VAULT_SYSTEMD}"
sudo rm -f "${VAULT_AGENT_SYSTEMD}"
sudo systemctl daemon-reload

echo "👥 Removing eos user, group, and sudoers..."
if id "${EOS_USER}" &>/dev/null; then
    sudo userdel "${EOS_USER}"
fi
if getent group "${EOS_GROUP}" &>/dev/null; then
    sudo groupdel "${EOS_GROUP}"
fi
sudo rm -f "${SUDOERS_FILE}"

echo "✅ EOS has been purged from the debian."