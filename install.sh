#!/usr/bin/env bash
set -euo pipefail
trap 'echo " Installation failed on line $LINENO"; exit 1' ERR

log() { echo "[$1] $2"; }

# --- Platform Detection ---
PLATFORM=""
IS_LINUX=false
IS_MAC=false
IS_RHEL=false
IS_DEBIAN=false

detect_platform() {
  case "$(uname -s)" in
    Linux)  
      PLATFORM="linux"
      IS_LINUX=true
      # Detect Linux distribution
      if [ -f /etc/redhat-release ] || [ -f /etc/centos-release ] || [ -f /etc/fedora-release ]; then
        IS_RHEL=true
        log INFO " Detected RHEL-based system"
      elif [ -f /etc/debian_version ] || command -v apt-get >/dev/null 2>&1; then
        IS_DEBIAN=true
        log INFO " Detected Debian-based system"
      fi
      ;;
    Darwin) PLATFORM="mac"; IS_MAC=true ;;
    *) log ERR " Unsupported OS: $(uname -s)"; exit 1 ;;
  esac
  log INFO " Detected platform: $PLATFORM"
}

# --- Globals ---
Eos_USER="eos"
Eos_BINARY_NAME="eos"
Eos_SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
Eos_BUILD_PATH="$Eos_SRC_DIR/$Eos_BINARY_NAME"
INSTALL_PATH="/usr/local/bin/$Eos_BINARY_NAME"

# Go installation settings
GO_VERSION="1.24.0"
GO_INSTALL_DIR="/usr/local"

# --- Directories ---
# These are the *default* system-wide paths.
# If Eos CLI supports user-specific configs, the Go application
# should handle XDG Base Directory specification (e.g., ~/.config/eos)
# when run as a non-root user.
if $IS_MAC; then
  SECRETS_DIR="$HOME/Library/Application Support/eos/secrets"
  CONFIG_DIR="$HOME/Library/Application Support/eos/config"
  LOG_DIR="$HOME/Library/Logs/eos"
else
  SECRETS_DIR="/var/lib/eos/secrets"
  CONFIG_DIR="/etc/eos"
  LOG_DIR="/var/log/eos"
fi

update_system_packages() {
  if $IS_RHEL; then
    log INFO " Updating RHEL-based system packages..."
    if command -v dnf >/dev/null 2>&1; then
      dnf update -y
    elif command -v yum >/dev/null 2>&1; then
      yum update -y
    else
      log ERR " Neither dnf nor yum found on RHEL-based system"
      exit 1
    fi
  elif $IS_DEBIAN; then
    log INFO " Updating Debian-based system packages..."
    
    # Check if dpkg lock is held
    local max_wait=60
    local wait_interval=5
    local waited=0
    
    while [ $waited -lt $max_wait ]; do
      if ! lsof /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
        # Lock is free, proceed with update
        break
      fi
      
      if [ $waited -eq 0 ]; then
        log INFO " Waiting for package management lock to be released..."
        log INFO " Another apt/dpkg process is running. Waiting up to ${max_wait} seconds..."
      fi
      
      sleep $wait_interval
      waited=$((waited + wait_interval))
      
      if [ $waited -lt $max_wait ]; then
        echo -n "."
      fi
    done
    
    if [ $waited -ge $max_wait ]; then
      log WARN " Package management lock still held after ${max_wait} seconds"
      log INFO " Checking what process is holding the lock..."
      
      # Try to identify the process
      local lock_pid=$(lsof /var/lib/dpkg/lock-frontend 2>/dev/null | grep -v COMMAND | awk '{print $2}' | head -1)
      if [ -n "$lock_pid" ]; then
        local proc_name=$(ps -p "$lock_pid" -o comm= 2>/dev/null || echo "unknown")
        log INFO " Process holding lock: $proc_name (PID: $lock_pid)"
        log ERR " Cannot proceed while another package manager is running"
        log INFO " Please wait for it to complete or terminate it, then run again"
        exit 100
      fi
    fi
    
    if [ $waited -gt 0 ] && [ $waited -lt $max_wait ]; then
      echo ""  # New line after dots
      log INFO " Lock released, proceeding with update"
    fi
    
    apt-get update -y
    apt-get upgrade -y
    log INFO " Cleaning up unused packages..."
    apt-get autoremove -y
    apt-get autoclean
  elif $IS_MAC; then
    log INFO " Skipping system update on macOS (use brew upgrade manually if needed)"
  fi
}

install_go() {
  local need_go_install=false
  local current_version=""

  # Check if Go needs to be installed or updated
  if ! command -v go >/dev/null 2>&1; then
    log INFO " Go is not installed"
    need_go_install=true
  else
    current_version=$(go version | awk '{print $3}' | sed 's/go//')
    log INFO " Detected Go version: $current_version"
    
    # Simple version comparison - check if current version is at least the required version
    if printf '%s\n%s\n' "$GO_VERSION" "$current_version" | sort -V | head -n1 | grep -q "^$GO_VERSION$"; then
      log INFO " Go is already up-to-date (version $current_version >= $GO_VERSION)"
    else
      log INFO " Go version is older (wanted: $GO_VERSION, found: $current_version)"
      need_go_install=true
    fi
  fi

  if [ "$need_go_install" = true ]; then
    if $IS_MAC; then
      log INFO " Installing Go via Homebrew..."
      if ! command -v brew >/dev/null 2>&1; then
        log ERR " Homebrew not found. Please install it first: https://brew.sh/"
        exit 1
      fi
      brew install go
    else
      # Linux installation - detect architecture
      local arch="amd64"
      case "$(uname -m)" in
        x86_64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l|armv6l) arch="armv6l" ;;
        *) log ERR " Unsupported architecture: $(uname -m)"; exit 1 ;;
      esac
      local os="linux"
      local go_tarball="go${GO_VERSION}.${os}-${arch}.tar.gz"
      local download_url="https://go.dev/dl/${go_tarball}"
      
      log INFO " Downloading Go ${GO_VERSION} from ${download_url}..."
      cd /tmp
      curl -LO "$download_url"
      
      if [ ! -f "$go_tarball" ]; then
        log ERR " Failed to download Go archive"
        exit 1
      fi
      
      # Verify download
      if ! file "$go_tarball" | grep -q "gzip compressed data"; then
        log ERR " Download failed or was not a valid tarball"
        exit 1
      fi
      
      log INFO " Extracting Go archive to ${GO_INSTALL_DIR}..."
      rm -rf "${GO_INSTALL_DIR}/go"
      tar -C "${GO_INSTALL_DIR}" -xzf "$go_tarball"
      
      # Set up environment variables system-wide
      local profile_file="/etc/profile.d/go.sh"
      log INFO " Setting up Go environment in ${profile_file}..."
      tee "${profile_file}" >/dev/null <<EOF
export PATH=\$PATH:/usr/local/go/bin
EOF
      
      # Symlink for global access
      if [ ! -f /usr/bin/go ]; then
        log INFO " Creating symlink for global Go access..."
        ln -sf /usr/local/go/bin/go /usr/bin/go
      fi
      
      # Clean up
      rm -f "$go_tarball"
      
      # Update PATH for current script execution
      export PATH="${GO_INSTALL_DIR}/go/bin:$PATH"
      
      log INFO " Go installed successfully"
    fi
  fi
  
  # Verify Go installation
  if command -v go >/dev/null 2>&1; then
    log INFO "Go version: $(go version)"
  else
    log ERR " Go installation verification failed"
    exit 1
  fi
}

install_github_cli() {
  if command -v gh >/dev/null 2>&1; then
    log INFO " GitHub CLI is already installed: $(gh --version | head -n1)"
    return
  fi
  
  log INFO " Installing GitHub CLI..."
  
  if $IS_MAC; then
    if ! command -v brew >/dev/null 2>&1; then
      log ERR " Homebrew not found. Please install it first: https://brew.sh/"
      exit 1
    fi
    brew install gh
  elif $IS_RHEL; then
    # Install dnf-plugins-core if not available
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y dnf-plugins-core
      
      # Remove any stale local repo
      if [ -f "/etc/yum.repos.d/opt_eos.repo" ]; then
        log INFO "Removing stale local repo: /etc/yum.repos.d/opt_eos.repo"
        rm -f /etc/yum.repos.d/opt_eos.repo
      fi
      
      # Add GitHub CLI repo if not already added
      if ! dnf repolist | grep -q "github-cli"; then
        dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
      fi
      
      dnf install -y gh
    elif command -v yum >/dev/null 2>&1; then
      # Fallback to yum for older RHEL systems
      yum install -y yum-utils
      yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
      yum install -y gh
    fi
  elif $IS_DEBIAN; then
    # Install GitHub CLI on Debian-based systems
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
    chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
    apt-get update
    apt-get install -y gh
  else
    log ERR " Unsupported Linux distribution for GitHub CLI installation"
    exit 1
  fi
  
  # Verify installation
  if command -v gh >/dev/null 2>&1; then
    log INFO " GitHub CLI installed: $(gh --version | head -n1)"
  else
    log ERR " GitHub CLI installation verification failed"
    exit 1
  fi
}

check_libvirt_deps() {
  if $IS_LINUX; then
    log INFO " Checking for libvirt development dependencies (REQUIRED)..."

    local missing_deps=()

    # Check for build tools (required for CGO)
    if ! command -v gcc >/dev/null 2>&1; then
      if $IS_DEBIAN; then
        missing_deps+=("build-essential")
      elif $IS_RHEL; then
        missing_deps+=("gcc" "make")
      fi
    fi

    # Check for pkg-config
    if ! command -v pkg-config >/dev/null 2>&1; then
      missing_deps+=("pkg-config")
    fi

    # Check for libvirt development files
    if ! pkg-config --exists libvirt 2>/dev/null; then
      if $IS_DEBIAN; then
        missing_deps+=("libvirt-dev")
      elif $IS_RHEL; then
        missing_deps+=("libvirt-devel")
      fi
    fi

    # Check for libvirt client libraries
    if ! pkg-config --exists libvirt-lxc 2>/dev/null; then
      if $IS_DEBIAN; then
        missing_deps+=("libvirt-daemon-system")
      elif $IS_RHEL; then
        missing_deps+=("libvirt-daemon-kvm")
      fi
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
      log WARN " Missing REQUIRED libvirt dependencies: ${missing_deps[*]}"
      log INFO " Eos requires libvirt development libraries to build"

      # Only auto-install if running as root
      if [[ "$EUID" -eq 0 ]]; then
        # Informed consent prompt (unless --yes flag provided)
        if [ "$AUTO_YES" = true ]; then
          log INFO " Auto-installing libvirt dependencies (--yes flag provided)"
          REPLY="y"
        else
          echo ""
          echo "The following packages need to be installed:"
          for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
          done
          echo ""
          read -p "Install these packages now? [y/N] " -n 1 -r
          echo ""
        fi

        if [[ $REPLY =~ ^[Yy]$ ]]; then
          log INFO " Installing required libvirt dependencies..."

          if $IS_DEBIAN; then
            apt-get install -y --no-install-recommends "${missing_deps[@]}"
          elif $IS_RHEL; then
            if command -v dnf >/dev/null 2>&1; then
              dnf install -y "${missing_deps[@]}"
            elif command -v yum >/dev/null 2>&1; then
              yum install -y "${missing_deps[@]}"
            fi
          fi

          # Update library cache so pkg-config can find the libraries
          log INFO " Updating library cache (ldconfig)"
          ldconfig 2>/dev/null || true

          log INFO " Libvirt dependencies installed successfully"
        else
          log ERR " Cannot continue without libvirt dependencies"
          log INFO " Install manually and run again:"
          if $IS_DEBIAN; then
            log INFO "   sudo apt-get install ${missing_deps[*]}"
          elif $IS_RHEL; then
            log INFO "   sudo yum install ${missing_deps[*]}"
          fi
          exit 1
        fi
      else
        log ERR " Cannot continue without libvirt. Install manually:"
        if $IS_DEBIAN; then
          log ERR "   sudo apt-get install ${missing_deps[*]}"
        elif $IS_RHEL; then
          log ERR "   sudo yum install ${missing_deps[*]}"
        fi
        exit 1
      fi
    else
      log INFO " All required libvirt dependencies are satisfied"
    fi
  elif $IS_MAC; then
    log ERR " Eos cannot be built on macOS - libvirt is required and not available on macOS"
    log ERR " Eos is designed to run on Linux servers only"
    exit 1
  fi
}

check_ceph_deps() {
  if $IS_LINUX; then
    log INFO " Checking for Ceph development dependencies (REQUIRED)..."

    local missing_deps=()

    # Check for pkg-config (should already be installed by check_libvirt_deps, but verify)
    if ! command -v pkg-config >/dev/null 2>&1; then
      missing_deps+=("pkg-config")
    fi

    # Check for librados development files
    if ! pkg-config --exists librados 2>/dev/null; then
      if $IS_DEBIAN; then
        missing_deps+=("librados-dev")
      elif $IS_RHEL; then
        missing_deps+=("librados-devel")
      fi
    fi

    # Check for librbd development files
    if ! pkg-config --exists librbd 2>/dev/null; then
      if $IS_DEBIAN; then
        missing_deps+=("librbd-dev")
      elif $IS_RHEL; then
        missing_deps+=("librbd-devel")
      fi
    fi

    # Check for libcephfs development files
    if ! pkg-config --exists libcephfs 2>/dev/null; then
      if $IS_DEBIAN; then
        missing_deps+=("libcephfs-dev")
      elif $IS_RHEL; then
        missing_deps+=("libcephfs-devel")
      fi
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
      log WARN " Missing REQUIRED Ceph dependencies: ${missing_deps[*]}"
      log INFO " Eos requires Ceph development libraries to build CephFS support"

      # Only auto-install if running as root
      if [[ "$EUID" -eq 0 ]]; then
        # Informed consent prompt (unless --yes flag provided)
        if [ "$AUTO_YES" = true ]; then
          log INFO " Auto-installing Ceph dependencies (--yes flag provided)"
          REPLY="y"
        else
          echo ""
          echo "The following packages need to be installed:"
          for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
          done
          echo ""
          read -p "Install these packages now? [y/N] " -n 1 -r
          echo ""
        fi

        if [[ $REPLY =~ ^[Yy]$ ]]; then
          log INFO " Installing required Ceph dependencies..."

          if $IS_DEBIAN; then
            apt-get install -y --no-install-recommends "${missing_deps[@]}"
          elif $IS_RHEL; then
            if command -v dnf >/dev/null 2>&1; then
              dnf install -y "${missing_deps[@]}"
            elif command -v yum >/dev/null 2>&1; then
              yum install -y "${missing_deps[@]}"
            fi
          fi

          # Update library cache so pkg-config can find the libraries
          log INFO " Updating library cache (ldconfig)"
          ldconfig 2>/dev/null || true

          log INFO " Ceph dependencies installed successfully"
        else
          log ERR " Cannot continue without Ceph dependencies"
          log INFO " Install manually and run again:"
          if $IS_DEBIAN; then
            log INFO "   sudo apt-get install ${missing_deps[*]}"
          elif $IS_RHEL; then
            log INFO "   sudo yum install ${missing_deps[*]}"
          fi
          exit 1
        fi
      else
        log ERR " Cannot continue without Ceph libraries. Install manually:"
        if $IS_DEBIAN; then
          log ERR "   sudo apt-get install ${missing_deps[*]}"
        elif $IS_RHEL; then
          log ERR "   sudo yum install ${missing_deps[*]}"
        fi
        exit 1
      fi
    else
      log INFO " All required Ceph dependencies are satisfied"
    fi
  elif $IS_MAC; then
    log ERR " Eos cannot be built on macOS - Ceph libraries are required and not available on macOS"
    log ERR " Eos is designed to run on Linux servers only"
    exit 1
  fi
}

check_prerequisites() {
  local go_found=false

  # 1. Check if 'go' is in the current PATH
  if command -v go >/dev/null; then
    log INFO " Go found in current PATH: $(command -v go)"
    go_found=true
  # 2. Check the standard /usr/local/go/bin/go location directly
  elif [[ -x "/usr/local/go/bin/go" ]]; then
    export PATH="/usr/local/go/bin:$PATH" # Temporarily add to PATH for this script's execution
    log INFO " Go found at standard installation path: /usr/local/go/bin/go"
    go_found=true
  # 3. Check the user's HOME/go/bin/go location directly (as a fallback)
  elif [[ -x "$HOME/go/bin/go" ]]; then
    export PATH="$HOME/go/bin:$PATH" # Temporarily add to PATH for this script's execution
    log INFO " Go found at user home path: $HOME/go/bin/go"
    go_found=true
  fi

  if ! $go_found; then
    log INFO " Go executable not found. Will install Go automatically."
    install_go
  else
    # Check Go version and potentially upgrade
    install_go
  fi

  # Install GitHub CLI if not present
  install_github_cli

  # Check for libvirt dependencies (required for KVM features)
  check_libvirt_deps

  # Check for Ceph dependencies (required for CephFS features)
  check_ceph_deps

  # Verify Go is now available
  log INFO "Go detected and ready. Version details: $(go version)"

  if $IS_LINUX; then
    for cmd in useradd usermod visudo stat; do
      command -v "$cmd" >/dev/null || { log ERR "Missing required command: $cmd"; exit 1; }
    done
  fi
}

update_from_git() {
  # Pull latest code from git if we're in a git repo
  if [ -d "$Eos_SRC_DIR/.git" ]; then
    log INFO " Pulling latest changes from GitHub..."
    cd "$Eos_SRC_DIR"

    # Save any local changes first
    if git diff --quiet && git diff --cached --quiet; then
      log INFO " No local changes detected"
    else
      log INFO " Stashing local changes before pull..."
      git stash push -m "install.sh auto-stash $(date +%Y%m%d-%H%M%S)"
    fi

    # Pull latest
    if git pull origin main; then
      log INFO " Successfully pulled latest changes"
    else
      log WARN " Git pull failed, continuing with existing code"
    fi
  else
    log INFO " Not a git repository, using existing code"
  fi
}

backup_existing_binary() {
  if [ -f "$INSTALL_PATH" ]; then
    BACKUP_PATH="${INSTALL_PATH}.backup.$(date +%Y%m%d-%H%M%S)"
    log INFO " Backing up existing binary to $BACKUP_PATH"
    if $IS_MAC; then
      sudo cp "$INSTALL_PATH" "$BACKUP_PATH"
    else
      cp "$INSTALL_PATH" "$BACKUP_PATH" 2>/dev/null || sudo cp "$INSTALL_PATH" "$BACKUP_PATH"
    fi
  fi
}

build_eos_binary() {
  log INFO " Building Eos with libvirt and Ceph support..."
  cd "$Eos_SRC_DIR"

  # Build to temp location first
  TEMP_BINARY="/tmp/eos-build-$(date +%s)"

  # Libvirt and Ceph are required - this should have been checked by check_libvirt_deps() and check_ceph_deps()
  # but double-check here for safety
  if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists libvirt 2>/dev/null; then
    log ERR " Libvirt development libraries not found - this should have been caught earlier"
    log ERR " Cannot build Eos without libvirt. Please run: sudo apt-get install libvirt-dev libvirt-daemon-system pkg-config"
    exit 1
  fi

  # Check each Ceph library individually for better error messages
  local missing_ceph_libs=()
  if ! pkg-config --exists librados 2>/dev/null; then
    missing_ceph_libs+=("librados")
  fi
  if ! pkg-config --exists librbd 2>/dev/null; then
    missing_ceph_libs+=("librbd")
  fi
  if ! pkg-config --exists libcephfs 2>/dev/null; then
    missing_ceph_libs+=("libcephfs")
  fi

  if [ ${#missing_ceph_libs[@]} -gt 0 ]; then
    log ERR " Missing Ceph libraries: ${missing_ceph_libs[*]}"
    log ERR " This should have been caught earlier by check_ceph_deps()"
    log ERR " Please run: sudo apt-get install librados-dev librbd-dev libcephfs-dev"
    log ERR " Then run ldconfig to update library cache: sudo ldconfig"
    exit 1
  fi

  log INFO " Building with CGO enabled for libvirt and Ceph"

  # Build with CGO enabled (required for libvirt and Ceph)
  CGO_ENABLED=1 GO111MODULE=on go build -o "$TEMP_BINARY" .

  if [ $? -ne 0 ]; then
    log ERR " Build failed"
    exit 1
  fi

  # Validate the binary
  if [ ! -f "$TEMP_BINARY" ]; then
    log ERR " Binary was not created"
    exit 1
  fi

  # Check size (should be at least 1MB)
  SIZE=$(stat -f%z "$TEMP_BINARY" 2>/dev/null || stat -c%s "$TEMP_BINARY" 2>/dev/null)
  if [ "$SIZE" -lt 1048576 ]; then
    log ERR " Binary is suspiciously small: $SIZE bytes"
    exit 1
  fi

  # Test the binary
  if ! "$TEMP_BINARY" --help >/dev/null 2>&1; then
    log ERR " Binary validation failed"
    exit 1
  fi

  # Move to expected location
  mv "$TEMP_BINARY" "$Eos_BUILD_PATH"
  log INFO " Build successful, binary size: $SIZE bytes"
}

show_existing_checksum() {
  if [ -f "$INSTALL_PATH" ]; then
    log INFO " Existing installed binary SHA256:"
    # Use command -v for robustness, or ensure shasum is on Mac
    command -v sha256sum >/dev/null && sha256sum "$INSTALL_PATH" || shasum -a 256 "$INSTALL_PATH"
  else
    log INFO " No existing installed binary to replace"
  fi
}

install_binary() {
  log INFO " Installing to $INSTALL_PATH"
  if $IS_MAC; then
    # On macOS, sudo is typically implied for /usr/local/bin
    sudo rm -rf "$INSTALL_PATH" || log ERR "Failed to remove existing binary at $INSTALL_PATH. Permissions issue?"
    sudo cp "$Eos_BUILD_PATH" "$INSTALL_PATH" || log ERR "Failed to copy binary to $INSTALL_PATH. Permissions issue?"
    sudo chmod 755 "$INSTALL_PATH" || log ERR "Failed to set permissions on $INSTALL_PATH."
  else
    # Linux handling: re-run with sudo if not already root
    if [[ "$EUID" -ne 0 ]]; then
      log INFO " Re-running with sudo to ensure proper permissions..."
      # Use `bash -c` to ensure the environment is inherited correctly when `sudo` re-runs
      exec sudo bash -c "export PATH=\"$PATH\"; \"$0\" \"$@\""
    fi
    rm -rf "$INSTALL_PATH" || log ERR "Failed to remove existing binary at $INSTALL_PATH. Permissions issue?"
    cp "$Eos_BUILD_PATH" "$INSTALL_PATH" || log ERR "Failed to copy binary to $INSTALL_PATH. Permissions issue?"
    chown root:root "$INSTALL_PATH" || log ERR "Failed to change ownership of $INSTALL_PATH."
    chmod 755 "$INSTALL_PATH" || log ERR "Failed to set permissions on $INSTALL_PATH."
  fi
}

show_new_checksum() {
  log INFO " New installed binary SHA256:"
  command -v sha256sum >/dev/null && sha256sum "$INSTALL_PATH" || shasum -a 256 "$INSTALL_PATH"
}

create_directories() {
  log INFO " Creating system-wide secrets, config, and log directories: $SECRETS_DIR, $CONFIG_DIR, $LOG_DIR"
  # Ensure directories are created as root if running with sudo
  mkdir -p "$SECRETS_DIR" "$CONFIG_DIR" "$LOG_DIR" || log ERR "Failed to create directories."
  chmod 700 "$SECRETS_DIR" || log ERR "Failed to set permissions on $SECRETS_DIR."
  chmod 755 "$LOG_DIR" || log ERR "Failed to set permissions on $LOG_DIR."

  # This is where the core logic for user-runnable commands comes in.
  # If Eos can run certain commands as a regular user, it needs to access
  # config/log/secret files *owned by that user*.
  # The recommended approach is for the Go application itself to determine
  # paths based on the current user and XDG Base Directory spec.
  # For the shell script, we can at least ensure base permissions are not overly restrictive for other users
  # while maintaining security for the 'eos' system user.

  # Example: Make config directory readable by others (if configs aren't secrets)
  # You might want to copy example configs here and make them user-readable
  # chmod 755 "$CONFIG_DIR" # Only if config files themselves are not sensitive or are templates.

  # Note: The `setup_linux_user` function later changes ownership to `eos:eos`.
  # This part is installing for the system service user.
}

main() {
  # Parse command line arguments
  local skip_update=false
  local auto_yes=false
  for arg in "$@"; do
    case $arg in
      --skip-update)
        skip_update=true
        log INFO " Skipping system package update (--skip-update flag provided)"
        shift
        ;;
      --yes|-y)
        auto_yes=true
        log INFO " Auto-accepting all prompts (--yes flag provided)"
        shift
        ;;
      --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --skip-update    Skip system package updates (apt/yum/dnf)"
        echo "  --yes, -y        Auto-accept all prompts (for automation/CI)"
        echo "  --help, -h       Show this help message"
        exit 0
        ;;
    esac
  done

  # Export for use in functions
  export AUTO_YES=$auto_yes
  
  detect_platform
  
  # Update system packages first (Linux only, requires root)
  if $IS_LINUX && ! $skip_update; then
    if [[ "$EUID" -eq 0 ]]; then
      update_system_packages
    else
      log INFO " Skipping system package update (not running as root)"
    fi
  fi
  
  check_prerequisites

  # Pull latest changes from git if available
  update_from_git

  # Backup existing binary before replacing
  backup_existing_binary

  # Build and validate
  build_eos_binary
  show_existing_checksum
  install_binary "$@"
  show_new_checksum
  create_directories
  echo
  log INFO " Eos installation complete!"
  log INFO "The 'eos' binary has been installed to '$INSTALL_PATH'."
  log INFO "This path is typically included in your user's PATH."
  log INFO "You should now be able to run 'eos --help' directly."
  echo
  log INFO "NOTE: Commands requiring elevated privileges (e.g., system configuration, user management, service control)"
  log INFO "      will still require 'sudo eos [command]'. For example: 'sudo eos create user'."
  log INFO "      Log files are located in '$LOG_DIR' and configuration in '$CONFIG_DIR'."
}

main "$@"
