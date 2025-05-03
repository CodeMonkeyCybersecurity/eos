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

# Ensure syslog group exists and add eos to it if missing
if getent group syslog > /dev/null; then
  if id -nG "$EOS_USER" | grep -qw "syslog"; then
    echo "✅ $EOS_USER is already in syslog group"
  else
    echo "➕ Adding $EOS_USER to syslog group"
    usermod -aG syslog "$EOS_USER" || {
      echo "❌ Failed to add $EOS_USER to syslog group"
      exit 1
    }
  fi
else
  echo "⚠️ syslog group not found — skipping group assignment"
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
  mkdir -p "$LOG_DIR" && echo "📁 Created $LOG_DIR"
fi

CURRENT_OWNER=$(stat -c "%U:%G" "$LOG_DIR" 2>/dev/null || echo "unknown:unknown")
if [ "$CURRENT_OWNER" != "$EOS_USER:$EOS_USER" ]; then
  chown "$EOS_USER:$EOS_USER" "$LOG_DIR" && echo "🔑 Ownership updated to $EOS_USER:$EOS_USER"
fi

chmod 750 "$LOG_DIR" && echo "🔒 Permissions set to 750"

echo "✅ Log directory ready: $LOG_DIR"

# --- BOOTSTRAP ADDITIONS BELOW ---

# Add eos sudoers entry
if [ ! -f /etc/sudoers.d/eos ]; then
  echo "⚙️ Adding eos to sudoers"
  echo "eos ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/eos
  chmod 440 /etc/sudoers.d/eos
  visudo -c || { echo "❌ Sudoers validation failed"; exit 1; }
  echo "✅ Sudoers entry added"
else
  echo "✅ eos sudoers entry already exists"
fi

# Show sudoers file
echo "📄 /etc/sudoers.d/eos content:"
cat /etc/sudoers.d/eos

# Summary
echo ""
echo "🎉 EOS installation and bootstrap complete!"
echo "👉 You can now run: eos bootstrap --yes"
echo "👉 To check installed binary: eos --help"