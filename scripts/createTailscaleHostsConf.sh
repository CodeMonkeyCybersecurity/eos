#!/bin/bash
# /scripts/createTailscaleHostsConf.sh
set -xe
../utils/checkSudo.sh
../utils/cyberMonkeyDir.sh
source ../variables.conf
# Define output file
# Generate Tailscale hosts YAML
echo "Generating Tailscale hosts YAML file..."
tailscale status --json | jq -r '.Peer[] | "- hostname: \(.HostName)\n  ip: \(.TailAddr)"' | grep -v "$(hostname)" > "$TAILSCALE_HOSTS_YAML"
ls -lah "$TAILSCALE_HOSTS_CONF"
cat "$TAILSCALE_HOSTS_CONF"
set +x
echo "finis"
