#!/bin/bash
set -euo pipefail

EOS_USER="eos"
EOS_SRC_DIR="/home/eos/eos-dev"
EOS_BINARY_NAME="eos"
EOS_BUILD_PATH="$EOS_SRC_DIR/$EOS_BINARY_NAME"
INSTALL_PATH="/usr/local/bin/$EOS_BINARY_NAME"
SECRETS_DIR="/var/lib/eos/secrets"
CONFIG_DIR="/etc/eos"

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
echo "🚚 Installing $EOS_BINARY_NAME to $INSTALL_PATH"
cp "$EOS_BINARY_NAME" "$INSTALL_PATH"
chown root:root "$INSTALL_PATH"
chmod 755 "$INSTALL_PATH"

# Create directories
echo "📁 Creating secrets and config directories"
mkdir -p "$SECRETS_DIR"
mkdir -p "$CONFIG_DIR"

chown -R "$EOS_USER:$EOS_USER" /var/lib/eos
chmod 750 /var/lib/eos
chmod 700 "$SECRETS_DIR"

echo "✅ Installation complete."
echo "👉 You can now run 'eos pandora read test-data'"
echo "🔐 You will be prompted for your own sudo password if not recently authenticated."
