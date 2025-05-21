#!/usr/bin/env bash
set -euo pipefail
trap 'echo "❌ Failed at line $LINENO"; exit 1' ERR

log() { echo "[$1] $2"; }

# Globals
EOS_USER="eos"
EOS_BINARY_NAME="eos"
EOS_SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
EOS_BUILD_PATH="$EOS_SRC_DIR/$EOS_BINARY_NAME"
PLATFORM=""
INSTALL_PATH=""

detect_platform() {
  case "${1:-}" in
    linux|Linux) PLATFORM="linux" ;;
    mac|darwin|Darwin) PLATFORM="mac" ;;
    windows|win|MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
    *)
      case "$(uname -s)" in
        Linux)   PLATFORM="linux" ;;
        Darwin)  PLATFORM="mac" ;;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
        *) log ERR "Unknown OS"; exit 1 ;;
      esac ;;
  esac
  log INFO "Detected platform: $PLATFORM"
}

get_install_path() {
  INSTALL_PATH="/usr/local/bin/$EOS_BINARY_NAME"
}

check_prerequisites() {
  if ! command -v go >/dev/null; then
    if [[ -x "$HOME/go/bin/go" ]]; then
      export PATH="$HOME/go/bin:$PATH"
      log INFO "Using fallback Go from ~/go/bin"
    else
      log ERR "Go not found in PATH"
      echo "👉 Install Go from https://go.dev/dl/"
      exit 1
    fi
  fi

  if [[ "$PLATFORM" == "linux" ]]; then
    for cmd in useradd usermod visudo stat; do
      command -v "$cmd" >/dev/null || {
        log ERR "Missing required command: $cmd"
        exit 1
      }
    done
  fi
}

build_eos_binary() {
  log INFO "Building EOS..."
  cd "$EOS_SRC_DIR"
  rm -f "$EOS_BINARY_NAME"
  go build -o "$EOS_BINARY_NAME" ./main.go
}

install_binary() {
  log INFO "Installing to $INSTALL_PATH"
  sudo cp "$EOS_BUILD_PATH" "$INSTALL_PATH"
  sudo chmod 755 "$INSTALL_PATH"
  [[ "$PLATFORM" == "linux" ]] && sudo chown root:root "$INSTALL_PATH"
}

setup_system_user() {
  if [[ "$PLATFORM" == "linux" ]] && ! id "$EOS_USER" &>/dev/null; then
    log INFO "Creating user: $EOS_USER"
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$EOS_USER"
    getent group syslog >/dev/null && sudo usermod -aG syslog "$EOS_USER"
  fi
}

configure_logs_and_dirs() {
  if [[ "$PLATFORM" == "linux" || "$PLATFORM" == "mac" ]]; then
    log INFO "Creating config and log directories"
    sudo mkdir -p /var/lib/eos/secrets /etc/eos /var/log/eos
    [[ "$PLATFORM" == "linux" ]] && sudo chown -R "$EOS_USER:$EOS_USER" /var/lib/eos
  fi
}

finalize_sudoers() {
  [[ "$PLATFORM" != "linux" ]] && return
  if [ ! -f /etc/sudoers.d/eos ]; then
    log INFO "Writing sudoers entry"
    echo "eos ALL=(ALL) NOPASSWD: $INSTALL_PATH" | sudo tee /etc/sudoers.d/eos >/dev/null
    sudo chmod 440 /etc/sudoers.d/eos
    sudo visudo -c
  fi
}

main() {
  detect_platform "${1:-}"
  [[ "$PLATFORM" == "windows" ]] && {
    log ERR "⚠️ Windows installation is not supported. Please use WSL or Linux/macOS."
    exit 1
  }

  get_install_path
  check_prerequisites
  build_eos_binary
  install_binary
  [[ "$PLATFORM" == "linux" ]] && setup_system_user
  configure_logs_and_dirs
  [[ "$PLATFORM" == "linux" ]] && finalize_sudoers
  log INFO "✅ EOS installed successfully! Run: eos --help"
}

main "$@"