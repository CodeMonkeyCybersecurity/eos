#!/bin/bash

# Exit if any command fails
set -e

# Define version and installation paths
GO_VERSION="1.24.0"
OS="linux"
ARCH="amd64"
DOWNLOAD_URL="https://go.dev/dl/go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
INSTALL_DIR="/usr/local"
PROFILE_FILE="/etc/profile.d/go.sh"
GH_REPO_URL="https://cli.github.com/packages/rpm/gh-cli.repo"

# Ensure script is run as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root or use sudo."
    exit 1
fi

echo "➡️ Updating system packages..."
dnf update -y

# Step 1: Install Go only if version differs or Go is missing
NEED_GO_INSTALL=false

if ! command -v go >/dev/null 2>&1; then
    echo "➡️ Go is not installed."
    NEED_GO_INSTALL=true
else
    CURRENT_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo "➡️ Detected Go version: $CURRENT_GO_VERSION"
    if [ "$CURRENT_GO_VERSION" != "$GO_VERSION" ]; then
        echo "➡️ Go version mismatch (wanted: $GO_VERSION, found: $CURRENT_GO_VERSION)"
        NEED_GO_INSTALL=true
    else
        echo "✅ Go is already up-to-date (version $GO_VERSION)."
    fi
fi

if [ "$NEED_GO_INSTALL" = true ]; then
    echo "➡️ Downloading Go ${GO_VERSION} from ${DOWNLOAD_URL}..."
    curl -LO "${DOWNLOAD_URL}"

    if [ ! -f "go${GO_VERSION}.${OS}-${ARCH}.tar.gz" ]; then
        echo "❌ Failed to download Go archive."
        exit 1
    fi

    echo "✅ Download complete."

    echo "➡️ Removing any existing Go installation from ${INSTALL_DIR}/go ..."
    rm -rf "${INSTALL_DIR}/go"

    echo "➡️ Extracting Go archive to ${INSTALL_DIR} ..."
    tar -C "${INSTALL_DIR}" -xzf "go${GO_VERSION}.${OS}-${ARCH}.tar.gz"

    echo "✅ Go installed in ${INSTALL_DIR}/go"

    # Set up environment variables system-wide
    echo "➡️ Setting up Go environment in ${PROFILE_FILE} ..."
    tee "${PROFILE_FILE}" >/dev/null <<EOF
export PATH=\$PATH:/usr/local/go/bin
EOF

    echo "✅ Go environment variables set. Reload your shell or source ${PROFILE_FILE}."

    # Clean up
    rm "go${GO_VERSION}.${OS}-${ARCH}.tar.gz"

    # Check installation
    echo "➡️ Checking Go version ..."
    source "${PROFILE_FILE}"
    go version
fi

# Symlink Go binary into /usr/bin to make sure it's available system-wide
if [ ! -f /usr/bin/go ]; then
    echo "➡️ Symlinking /usr/local/go/bin/go to /usr/bin/go for global access..."
    ln -sf /usr/local/go/bin/go /usr/bin/go
fi

# Step 2: Install gh if missing
if ! command -v gh >/dev/null 2>&1; then
    echo "➡️ GitHub CLI (gh) not found. Installing via GitHub's official RPM repo..."
    dnf install -y dnf-plugins-core

    # Defensive: remove any bad local repo accidentally created before
    if [ -f "/etc/yum.repos.d/opt_eos.repo" ]; then
        echo "⚠️ Removing stale local repo: /etc/yum.repos.d/opt_eos.repo"
        rm -f /etc/yum.repos.d/opt_eos.repo
    fi

    # Add GH repo only if not already added
    if ! dnf repolist | grep -q "github-cli"; then
        dnf config-manager --add-repo "$GH_REPO_URL"
    fi

    dnf install -y gh
else
    echo "✅ gh is already installed: $(gh --version)"
fi

echo "✅ All done!"
