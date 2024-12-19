#!/bin/bash
# /scripts/createTailscaleHostsYaml.sh

set -xe

../utils/checkSudo.sh
CYBERMONKEY_DIR=$("../utils/cyberMonkeyDir.sh") || { echo "cyberMonkeyDir.sh failed"; exit 1; }

# Define output file
TAILSCALE_HOSTS_YAML="$CYBERMONKEY_DIR/tailscaleHosts.yaml"

# Generate Tailscale hosts YAML
echo "Generating Tailscale hosts YAML file..."
tailscale status --json | jq -r '.Peer[] | "- hostname: \(.HostName)\n  ip: \(.TailAddr)"' | grep -v "$(hostname)" > "$TAILSCALE_HOSTS_YAML"

# Completion message
echo "Tailscale hosts YAML file created successfully at $TAILSCALE_HOSTS_YAML"

set +x

echo "finis"
