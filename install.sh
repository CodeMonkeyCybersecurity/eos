#!/bin/bash
set -euo pipefail

EOS_USER="eos"
EOS_SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
EOS_BINARY_NAME="eos"
EOS_BUILD_PATH="$EOS_SRC_DIR/$EOS_BINARY_NAME"
INSTALL_PATH="/usr/local/bin/$EOS_BINARY_NAME"
SECRETS_DIR="/var/lib/eos/secrets"
CONFIG_DIR="/etc/eos"
LOG_DIR="/var/log/eos"
LOG_USER="eos"
LOG_GROUP="eos"

# Ensure running as root
if [[ "$EUID" -ne 0 ]]; then
  echo "🔐 This script requires root privileges. Re-running with sudo..."
  exec sudo "$0" "$@"
fi

echo "📦 Building EOS from $EOS_SRC_DIR..."
if [[ ! -d "$EOS_SRC_DIR" ]]; then
  echo "❌ Source directory $EOS_SRC_DIR not found"
  exit 1
fi

cd "$EOS_SRC_DIR"
go build -o "$EOS_BINARY_NAME" ./main.go

# Ensure eos user exists
if ! id "$EOS_USER" &>/dev/null; then
  echo "👤 Creating system user: $EOS_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$EOS_USER"
fi

# Install binary
echo "🧹 Cleaning old EOS binary..."
rm -rf "$INSTALL_PATH"
echo "🚚 Installing $EOS_BINARY_NAME to $INSTALL_PATH"
cp "$EOS_BINARY_NAME" "$INSTALL_PATH"
chown root:root "$INSTALL_PATH"
chmod 755 "$INSTALL_PATH"

# Create directories
echo "📁 Creating secrets and config directories"
mkdir -p "$SECRETS_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p /var/lib/eos

chown -R "$EOS_USER:$EOS_USER" /var/lib/eos
chmod 750 /var/lib/eos
chmod 700 "$SECRETS_DIR"

echo "🔧 Setting up log directory: $LOG_DIR"

if [ ! -d "$LOG_DIR" ]; then
  if mkdir -p "$LOG_DIR"; then
    echo "📁 Created $LOG_DIR"
  else
    echo "❌ Failed to create $LOG_DIR"
    exit 1
  fi
else
  echo "📁 Log directory already exists"
fi

# Only chown if needed
CURRENT_OWNER=$(stat -c "%U:%G" "$LOG_DIR" 2>/dev/null || echo "unknown:unknown")
if [ "$CURRENT_OWNER" != "$EOS_USER:$EOS_USER" ]; then
  if chown "$EOS_USER:$EOS_USER" "$LOG_DIR"; then
    echo "🔑 Ownership updated to $EOS_USER:$EOS_USER"
  else
    echo "❌ Failed to set ownership on $LOG_DIR"
    exit 1
  fi
fi

# Set permissions
if chmod 750 "$LOG_DIR"; then
  echo "🔒 Permissions set to 750"
else
  echo "❌ Failed to set permissions on $LOG_DIR"
  exit 1
fi

echo "✅ Log directory ready: $LOG_DIR"

echo "✅ Installation complete."
echo "👉 You can now run 'eos --help' to confirm install"
echo "🔐 You will be prompted for your own  password if not recently authenticated."
