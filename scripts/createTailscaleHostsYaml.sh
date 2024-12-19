#!/bin/bash
# /scripts/createTailscaleHostsYaml.sh
set -xe
../utils/checkSudo.sh
../utils/cyberMonkeyDir.sh
# Define output file
TAILSCALE_HOSTS_YAML="/opt/cyberMonkey/tailscaleHosts.yaml"
# Generate Tailscale hosts YAML
echo "Generating Tailscale hosts YAML file..."
tailscale status --json | jq -r '.Peer[] | "- hostname: \(.HostName)\n  ip: \(.TailAddr)"' | grep -v "$(hostname)" > "$TAILSCALE_HOSTS_YAML"
ls -lah "$TAILSCALE_HOSTS_YAML"
cat "$TAILSCALE_HOSTS_YAML"
set +x
echo "finis"
