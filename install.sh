#!/bin/bash
set -euo pipefail

trap 'echo "❌ Installation failed on line $LINENO"; exit 1' ERR

EOS_USER="eos"
EOS_SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
EOS_BINARY_NAME="eos"
EOS_BUILD_PATH="$EOS_SRC_DIR/$EOS_BINARY_NAME"
INSTALL_PATH="/usr/local/bin/$EOS_BINARY_NAME"
SECRETS_DIR="/var/lib/eos/secrets"
CONFIG_DIR="/etc/eos"
LOG_DIR="/var/log/eos"
LOG_USER="$EOS_USER"
LOG_GROUP="$EOS_USER"

# --- Detect Go explicitly and safely ---
GO_PATH=$(command -v go || true)
if [[ -z "$GO_PATH" ]]; then
  # Fallback: try the original user's path
  SUDO_USER_HOME=$(eval echo ~"${SUDO_USER:-$USER}")
  if [[ -x "$SUDO_USER_HOME/go/bin/go" ]]; then
    export PATH="$SUDO_USER_HOME/go/bin:$PATH"
    echo "🧩 Using fallback Go path: $SUDO_USER_HOME/go/bin"
  else
    echo "❌ Required command 'go' not found in PATH"
    echo "👉 Ensure Go is installed and visible to root"
    exit 1
  fi
fi

# Check for required commands
for cmd in useradd usermod visudo stat; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "❌ Required command '$cmd' not found"
    exit 1
  }
done

# If not running as root, switch to sudo after build
if [[ "$EUID" -ne 0 ]]; then
  echo "📦 Building EOS as regular user from $EOS_SRC_DIR..."
  if [[ ! -d "$EOS_SRC_DIR" ]]; then
    echo "❌ Source directory $EOS_SRC_DIR not found"
    exit 1
  fi
  cd "$EOS_SRC_DIR"
  rm -f "$EOS_BINARY_NAME"
  go build -o "$EOS_BINARY_NAME" ./main.go || { echo "❌ Build failed"; exit 1; }
  echo "🔐 Re-running with sudo..."
  exec sudo "$0" "$@"
fi

# Build as root to ensure rebuild always happens
echo "📦 Rebuilding EOS as root from $EOS_SRC_DIR..."
cd "$EOS_SRC_DIR"
rm -f "$EOS_BINARY_NAME"
go build -o "$EOS_BINARY_NAME" ./main.go || { echo "❌ Build failed as root"; exit 1; }

# Ensure eos user exists
if ! id "$EOS_USER" &>/dev/null; then
  echo "👤 Creating system user: $EOS_USER"
  useradd --system --no-create-home --shell /usr/sbin/nologin "$EOS_USER"
fi

# Ensure syslog group exists and add eos to it
if getent group syslog > /dev/null; then
  if id -nG "$EOS_USER" | grep -qw "syslog"; then
    echo "✅ $EOS_USER is already in syslog group"
  else
    echo "➕ Adding $EOS_USER to syslog group"
    usermod -aG syslog "$EOS_USER"
  fi
else
  echo "⚠️ syslog group not found — skipping group assignment"
fi

# Optional hardcoded symlinks (you may remove if redundant)
ln -sf /usr/local/go/bin/go /usr/bin/go 2>/dev/null || true
ln -sf /usr/local/go/bin/gofmt /usr/bin/gofmt 2>/dev/null || true
ln -sf /usr/local/bin/eos /usr/bin/eos 2>/dev/null || true

# Show SHA256 checksum of the existing installed binary (if present)
if [ -f "$INSTALL_PATH" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    echo "🔍 Existing installed binary SHA256:"
    sha256sum "$INSTALL_PATH"
  elif command -v shasum >/dev/null 2>&1; then
    echo "🔍 Existing installed binary SHA256:"
    shasum -a 256 "$INSTALL_PATH"
  else
    echo "⚠️ Neither sha256sum nor shasum found; skipping SHA256 display"
  fi
else
  echo "ℹ️ No existing installed binary to checksum"
fi

# Always replace installed binary
rm -f "$INSTALL_PATH"
echo "🚚 Installing $EOS_BINARY_NAME to $INSTALL_PATH"
cp "$EOS_BUILD_PATH" "$INSTALL_PATH"
chown root:root "$INSTALL_PATH"
chmod 755 "$INSTALL_PATH"

# Show SHA256 checksum of the new installed binary
if command -v sha256sum >/dev/null 2>&1; then
  echo "🔍 New installed binary SHA256:"
  sha256sum "$INSTALL_PATH"
elif command -v shasum >/dev/null 2>&1; then
  echo "🔍 New installed binary SHA256:"
  shasum -a 256 "$INSTALL_PATH"
else
  echo "⚠️ Neither sha256sum nor shasum found; skipping SHA256 display"
fi

# Create directories safely
echo "📁 Creating secrets and config directories"
mkdir -p "$SECRETS_DIR" "$CONFIG_DIR" /var/lib/eos
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

# Add eos sudoers entry (restrict to eos binary only)
if [ ! -f /etc/sudoers.d/eos ]; then
  echo "⚙️ Adding eos to sudoers"
  echo "eos ALL=(ALL) NOPASSWD: $INSTALL_PATH" > /etc/sudoers.d/eos
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