#!/bin/bash
# /scripts/createTailscaleHostsYaml.sh

set -xe

../utils/checkSudo.sh
../utils/cyberMonkeyDir.sh

TAILSCALE_HOSTS_YAML="$CYBERMONKEY_DIR/tailscaleHosts.yaml"

tailscale status --json | jq -r '.Peer[] | "- hostname: \(.HostName)\n  ip: \(.TailAddr)"' | grep -v "$(hostname)" > "$TAILSCALE_HOSTS_YAML"

set +x

echo "finis"
