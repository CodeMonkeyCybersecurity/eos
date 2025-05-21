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
  if ! command -v go >/dev/null; then
    if [[ -x "$HOME/go/bin/go" ]]; then
      export PATH="$HOME/go/bin:$PATH"
      log INFO "🧩 Using fallback Go path: $HOME/go/bin/go"
    else
      log ERR "❌ Go not found in PATH"
      if $IS_MAC; then
        echo "👉 Install it with: brew install go"
      else
        echo "👉 Install it from https://go.dev/dl/"
      fi
      exit 1
    fi
  fi

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
  go build -o "$EOS_BINARY_NAME" .
}

show_existing_checksum() {
  if [ -f "$INSTALL_PATH" ]; then
    log INFO "🔍 Existing installed binary SHA256:"
    command -v sha256sum >/dev/null && sha256sum "$INSTALL_PATH" || shasum -a 256 "$INSTALL_PATH"
  else
    log INFO "ℹ️ No existing installed binary to replace"
  fi
}

install_binary() {
  log INFO "🚚 Installing to $INSTALL_PATH"
  if $IS_MAC; then
    sudo rm -f "$INSTALL_PATH"
    sudo cp "$EOS_BUILD_PATH" "$INSTALL_PATH"
    sudo chmod 755 "$INSTALL_PATH"
  else
    if [[ "$EUID" -ne 0 ]]; then
      log INFO "🔐 Re-running with sudo..."
      exec sudo "$0" "$@"
    fi
    rm -f "$INSTALL_PATH"
    cp "$EOS_BUILD_PATH" "$INSTALL_PATH"
    chown root:root "$INSTALL_PATH"
    chmod 755 "$INSTALL_PATH"
  fi
}

show_new_checksum() {
  log INFO "🔍 New installed binary SHA256:"
  command -v sha256sum >/dev/null && sha256sum "$INSTALL_PATH" || shasum -a 256 "$INSTALL_PATH"
}

create_directories() {
  log INFO "📁 Creating secrets, config, and log directories"
  mkdir -p "$SECRETS_DIR" "$CONFIG_DIR" "$LOG_DIR"
  chmod 700 "$SECRETS_DIR"
  chmod 755 "$LOG_DIR"
}

setup_linux_user() {
  if $IS_LINUX; then
    if ! id "$EOS_USER" &>/dev/null; then
      log INFO "👤 Creating system user: $EOS_USER"
      useradd --system --no-create-home --shell /usr/sbin/nologin "$EOS_USER"
    fi

    if getent group syslog >/dev/null && ! id -nG "$EOS_USER" | grep -qw syslog; then
      log INFO "➕ Adding $EOS_USER to syslog group"
      usermod -aG syslog "$EOS_USER"
    fi

    chown -R "$EOS_USER:$EOS_USER" /var/lib/eos
    chmod 750 /var/lib/eos
    chown "$EOS_USER:$EOS_USER" "$LOG_DIR"
    chmod 750 "$LOG_DIR"
  fi
}

add_sudoers_entry() {
  if $IS_LINUX && [ ! -f /etc/sudoers.d/eos ]; then
    log INFO "⚙️ Adding sudoers entry"
    echo "eos ALL=(ALL) NOPASSWD: $INSTALL_PATH" > /etc/sudoers.d/eos
    chmod 440 /etc/sudoers.d/eos
    visudo -c || { log ERR "❌ Sudoers validation failed"; exit 1; }
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
  log INFO "👉 Run: eos --help"
}

main "$@"