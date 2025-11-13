#!/bin/bash
# Deploy Eos to production servers
# Usage: ./scripts/deploy-to-servers.sh [server1] [server2] ...

set -euo pipefail

SERVERS="${@:-vhost2}"  # Default to vhost2, or use provided list
BUILD_DIR="/tmp/eos-deploy-$(date +%s)"
INSTALL_PATH="/usr/local/bin/eos"

echo "=== Eos Deployment Script ==="
echo "Servers: $SERVERS"
echo ""

# Step 1: Build locally
echo "[1/4] Building Eos locally..."
go build -o "$BUILD_DIR/eos" ./cmd/
if [ $? -ne 0 ]; then
    echo "ERROR: Build failed"
    exit 1
fi

# Step 2: Run tests
echo "[2/4] Running tests..."
go test -v ./pkg/repository
if [ $? -ne 0 ]; then
    echo "ERROR: Tests failed"
    exit 1
fi

echo "[3/4] Deploying to servers..."
for server in $SERVERS; do
    echo "  → Deploying to $server..."

    # Copy binary
    scp "$BUILD_DIR/eos" "$server:/tmp/eos-new"

    # Install with atomic swap (minimizes downtime)
    ssh "$server" "sudo mv /tmp/eos-new $INSTALL_PATH && sudo chmod +x $INSTALL_PATH"

    # Verify version
    VERSION=$(ssh "$server" "$INSTALL_PATH --version" || echo "UNKNOWN")
    echo "    ✓ Deployed. Version: $VERSION"
done

echo "[4/4] Cleanup..."
rm -rf "$BUILD_DIR"

echo ""
echo "✓ Deployment complete!"
echo ""
echo "Verify with:"
for server in $SERVERS; do
    echo "  ssh $server 'eos --version'"
done
