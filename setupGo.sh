#!/bin/bash

set -euo pipefail

GO_VERSION="1.24.0"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
INSTALL_DIR="/usr/local"
GO_URL="https://go.dev/dl/${GO_TARBALL}"

echo "🔧 Installing Go ${GO_VERSION} to ${INSTALL_DIR}..."

cd "$INSTALL_DIR"

# Remove any existing Go installation
if [ -d "${INSTALL_DIR}/go" ]; then
    echo "⚠️  Existing Go installation detected. Removing..."
    rm -rf go
fi

# Download Go
echo "⬇️  Downloading ${GO_URL}..."
curl -O "$GO_URL"

# Extract
echo "📦 Extracting ${GO_TARBALL}..."
tar -xzf "$GO_TARBALL"

# Clean up
rm -f "$GO_TARBALL"

# Update PATH for current shell
export PATH="${INSTALL_DIR}/go/bin:$PATH"

echo ""
echo "✅ Go installed!"
go version

echo ""
echo "💡 To persist this PATH, add the following to your shell config:"
echo "    export PATH=\"${INSTALL_DIR}/go/bin:\$PATH\""
echo ""

echo "🎉 Done. Go is ready to use."