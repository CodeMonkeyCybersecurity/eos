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
EOS_REPO_URL="https://github.com/CodeMonkeyCybersecurity/eos.git"
INSTALL_DIR="/opt"

# Ensure script is run as root or with sudo
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root or use sudo."
    exit 1
fi

echo "➡️ Updating system packages..."
dnf update -y


echo "➡️ Downloading Go ${GO_VERSION} from ${DOWNLOAD_URL}..."
curl -LO "${DOWNLOAD_URL}"

if [ ! -f "go${GO_VERSION}.${OS}-${ARCH}.tar.gz" ]; then
    echo "❌ Failed to download Go archive."
    exit 1
fi

echo "✅ Download complete."

echo "➡️ Removing any existing Go installation from ${INSTALL_DIR}/go ..."
sudo rm -rf "${INSTALL_DIR}/go"

echo "➡️ Extracting Go archive to ${INSTALL_DIR} ..."
sudo tar -C "${INSTALL_DIR}" -xzf "go${GO_VERSION}.${OS}-${ARCH}.tar.gz"

echo "✅ Go installed in ${INSTALL_DIR}/go"

# Set up environment variables system-wide
echo "➡️ Setting up Go environment in ${PROFILE_FILE} ..."
sudo tee "${PROFILE_FILE}" >/dev/null <<EOF
export PATH=\$PATH:/usr/local/go/bin
EOF

echo "✅ Go environment variables set. Reload your shell or source ${PROFILE_FILE}."

# Clean up
rm "go${GO_VERSION}.${OS}-${ARCH}.tar.gz"

# Check installation
echo "➡️ Checking Go version ..."
source "${PROFILE_FILE}"
go version


# Step 2: Install gh if missing
if ! command -v gh >/dev/null 2>&1; then
    echo "➡️ GitHub CLI (gh) not found. Installing via GitHub's official RPM repo..."
    dnf install -y dnf-plugins-core
    dnf config-manager --add-repo "$GH_REPO_URL"
    dnf install -y gh
else
    echo "✅ gh is already installed: $(gh --version)"
fi


echo "✅ All done!"
