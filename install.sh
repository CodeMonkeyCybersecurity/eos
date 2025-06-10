#!/usr/bin/env bash
set -euo pipefail
trap 'echo "❌ Installation failed on line $LINENO"; exit 1' ERR

log() { echo "[$1] $2"; }

# --- Platform Detection ---
PLATFORM=""
IS_LINUX=false
IS_MAC=false

detect_platform() {
  case "$(uname -s)" in
    Linux)  PLATFORM="linux"; IS_LINUX=true ;;
    Darwin) PLATFORM="mac";   IS_MAC=true ;;
    *) log ERR "❌ Unsupported OS: $(uname -s)"; exit 1 ;;
  esac
  log INFO "📦 Detected platform: $PLATFORM"
}

# --- Globals ---
EOS_USER="eos"
EOS_BINARY_NAME="eos"
EOS_SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
EOS_BUILD_PATH="$EOS_SRC_DIR/$EOS_BINARY_NAME"
INSTALL_PATH="/usr/local/bin/$EOS_BINARY_NAME"

# --- Directories ---
if $IS_MAC; then
  SECRETS_DIR="$HOME/Library/Application Support/eos/secrets"
  CONFIG_DIR="$HOME/Library/Application Support/eos/config"
  LOG_DIR="$HOME/Library/Logs/eos"
else
  SECRETS_DIR="/var/lib/eos/secrets"
  CONFIG_DIR="/etc/eos"
  LOG_DIR="/var/log/eos"
fi

check_prerequisites() {
  local go_found=false

  # 1. Check if 'go' is in the current PATH
  if command -v go >/dev/null; then
    log INFO "✅ Go found in current PATH: $(command -v go)"
    go_found=true
  # 2. Check the standard /usr/local/go/bin/go location directly
  elif [[ -x "/usr/local/go/bin/go" ]]; then
    export PATH="/usr/local/go/bin:$PATH" # Temporarily add to PATH for this script's execution
    log INFO "✅ Go found at standard installation path: /usr/local/go/bin/go"
    go_found=true
  # 3. Check the user's HOME/go/bin/go location directly (as a fallback)
  elif [[ -x "$HOME/go/bin/go" ]]; then
    export PATH="$HOME/go/bin:$PATH" # Temporarily add to PATH for this script's execution
    log INFO "✅ Go found at user home path: $HOME/go/bin/go"
    go_found=true
  fi

  if ! $go_found; then
    log ERR "❌ Go executable not found anywhere (PATH, /usr/local/go/bin, $HOME/go/bin)."
    if $IS_MAC; then
      echo "👉 Install it with: brew install go"
    else
      echo "👉 Install it from https://go.dev/dl/ or run ./setupGo.sh"
    fi
    exit 1
  fi

  # Confirm the detected Go version
  log INFO "Go detected and ready. Version details: $(go version)"

  if $IS_LINUX; then
    for cmd in useradd usermod visudo stat; do
      command -v "$cmd" >/dev/null || { log ERR "Missing required command: $cmd"; exit 1; }
    done
  fi
}

build_eos_binary() {
  log INFO "⚙️ Building EOS..."
  cd "$EOS_SRC_DIR"
  rm -f "$EOS_BINARY_NAME"
  # Use the 'go' command which should now be in PATH due to check_prerequisites
  go build -o "$EOS_BINARY_NAME" .
}

show_existing_checksum() {
  if [ -f "$INSTALL_PATH" ]; then
    log INFO "🔍 Existing installed binary SHA256:"
    # Use command -v for robustness, or ensure shasum is on Mac
    command -v sha256sum >/dev/null && sha256sum "$INSTALL_PATH" || shasum -a 256 "$INSTALL_PATH"
  else
    log INFO "ℹ️ No existing installed binary to replace"
  fi
}

install_binary() {
  log INFO "🚚 Installing to $INSTALL_PATH"
  if $IS_MAC; then
    # On macOS, sudo is typically implied for /usr/local/bin
    sudo rm -f "$INSTALL_PATH" || log ERR "Failed to remove existing binary at $INSTALL_PATH. Permissions issue?"
    sudo cp "$EOS_BUILD_PATH" "$INSTALL_PATH" || log ERR "Failed to copy binary to $INSTALL_PATH. Permissions issue?"
    sudo chmod 755 "$INSTALL_PATH" || log ERR "Failed to set permissions on $INSTALL_PATH."
  else
    # Linux handling: re-run with sudo if not already root
    if [[ "$EUID" -ne 0 ]]; then
      log INFO "🔐 Re-running with sudo to ensure proper permissions..."
      # Use `bash -c` to ensure the environment is inherited correctly when `sudo` re-runs
      exec sudo bash -c "export PATH=\"$PATH\"; \"$0\" \"$@\""
    fi
    rm -f "$INSTALL_PATH" || log ERR "Failed to remove existing binary at $INSTALL_PATH. Permissions issue?"
    cp "$EOS_BUILD_PATH" "$INSTALL_PATH" || log ERR "Failed to copy binary to $INSTALL_PATH. Permissions issue?"
    chown root:root "$INSTALL_PATH" || log ERR "Failed to change ownership of $INSTALL_PATH."
    chmod 755 "$INSTALL_PATH" || log ERR "Failed to set permissions on $INSTALL_PATH."
  fi
}

show_new_checksum() {
  log INFO "🔍 New installed binary SHA256:"
  command -v sha256sum >/dev/null && sha256sum "$INSTALL_PATH" || shasum -a 256 "$INSTALL_PATH"
}

create_directories() {
  log INFO "📁 Creating secrets, config, and log directories"
  # Ensure directories are created as root if running with sudo
  mkdir -p "$SECRETS_DIR" "$CONFIG_DIR" "$LOG_DIR" || log ERR "Failed to create directories."
  chmod 700 "$SECRETS_DIR" || log ERR "Failed to set permissions on $SECRETS_DIR."
  chmod 755 "$LOG_DIR" || log ERR "Failed to set permissions on $LOG_DIR."
}

setup_linux_user() {
  if $IS_LINUX; then
    if ! id "$EOS_USER" &>/dev/null; then
      log INFO "👤 Creating system user: $EOS_USER"
      useradd --system --no-create-home --shell /usr/sbin/nologin "$EOS_USER" || log ERR "Failed to create user $EOS_USER."
    fi

    # Check if syslog group exists and user is not already in it
    if getent group syslog >/dev/null && ! id -nG "$EOS_USER" | grep -qw syslog; then
      log INFO "➕ Adding $EOS_USER to syslog group"
      usermod -aG syslog "$EOS_USER" || log ERR "Failed to add user $EOS_USER to syslog group."
    fi

    # Ensure ownership and permissions are correct
    chown -R "$EOS_USER:$EOS_USER" /var/lib/eos || log ERR "Failed to change ownership of /var/lib/eos."
    chmod 750 /var/lib/eos || log ERR "Failed to set permissions on /var/lib/eos."
    chown "$EOS_USER:$EOS_USER" "$LOG_DIR" || log ERR "Failed to change ownership of $LOG_DIR."
    chmod 750 "$LOG_DIR" || log ERR "Failed to set permissions on $LOG_DIR."
  fi
}

add_sudoers_entry() {
  if $IS_LINUX && [ ! -f /etc/sudoers.d/eos ]; then
    log INFO "⚙️ Adding sudoers entry for $EOS_USER"
    echo "$EOS_USER ALL=(ALL) NOPASSWD: $INSTALL_PATH" | tee /etc/sudoers.d/eos > /dev/null \
      || { log ERR "Failed to write sudoers entry."; exit 1; }
    chmod 440 /etc/sudoers.d/eos || { log ERR "Failed to set permissions on sudoers file."; exit 1; }
    visudo -c || { log ERR "❌ Sudoers validation failed. Please check /etc/sudoers.d/eos manually."; exit 1; }
    log INFO "Sudoers entry validated."
  else
    log INFO "Sudoers entry already exists or not applicable for this OS."
  fi
}

main() {
  detect_platform
  check_prerequisites
  build_eos_binary
  show_existing_checksum
  install_binary "$@"
  show_new_checksum
  create_directories
  setup_linux_user
  add_sudoers_entry
  echo
  log INFO "🎉 EOS installation complete!"
  log INFO "👉 You can now run: sudo $EOS_BINARY_NAME --help (if installed globally for root)"
  log INFO "👉 Or if your user's PATH is updated: $EOS_BINARY_NAME --help"
}

main "$@"
