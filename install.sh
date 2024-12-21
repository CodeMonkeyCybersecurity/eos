#!/bin/bash
VERSION="v1.0.0"
OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

# Adjust ARCH for compatibility
if [ "$ARCH" == "x86_64" ]; then
  ARCH="amd64"
elif [ "$ARCH" == "arm64" ]; then
  ARCH="arm64"
fi

# Download binary
curl -L -o eos "https://https://github.com/CodeMonkeyCybersecurity/eos/releases/download/$VERSION/eos-$OS-$ARCH"
chmod +x eos
sudo mv eos /usr/local/bin/

echo "Eos installed successfully!"