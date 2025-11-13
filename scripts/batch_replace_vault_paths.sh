#!/usr/bin/env bash
# batch_replace_vault_paths.sh
# Automated batch replacement of hardcoded vault paths with constants

set -euo pipefail

REPO_ROOT="/Users/henry/Dev/eos"
BACKUP_DIR="/tmp/vault_path_replacement_backup_$(date +%s)"

echo "Creating backup at: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Backup all files we're about to modify
FILES_TO_UPDATE=(
    "pkg/vault/cleanup/hardening.go"
    "pkg/vault/cleanup/verify.go"
    "pkg/vault/secure_init_reader.go"
    "pkg/debug/vault/diagnostics.go"
    "pkg/debug/vault/tls.go"
    "pkg/servicestatus/vault.go"
    "pkg/servicestatus/consul.go"
    "pkg/sync/connectors/consul_vault.go"
    "pkg/environment/server_detection.go"
    "pkg/inspect/services.go"
    "pkg/ubuntu/apparmor.go"
    "pkg/consul/remove.go"
    "pkg/nuke/assess.go"
    "cmd/debug/bootstrap.go"
    "cmd/read/verify.go"
)

for file in "${FILES_TO_UPDATE[@]}"; do
    full_path="$REPO_ROOT/$file"
    if [[ -f "$full_path" ]]; then
        echo "Backing up: $file"
        cp "$full_path" "$BACKUP_DIR/$(basename $file).bak"
    fi
done

echo ""
echo "Performing batch replacements..."
echo ""

# Function to replace in a file
replace_in_file() {
    local file=$1
    local pattern=$2
    local replacement=$3
    local description=$4

    if [[ -f "$file" ]]; then
        if grep -q "$pattern" "$file" 2>/dev/null; then
            echo "  [$description] Replacing in $(basename $file)"
            sed -i '' "s|$pattern|$replacement|g" "$file"
        fi
    fi
}

# Binary paths
echo "=== Replacing Binary Paths ==="
for file in "${FILES_TO_UPDATE[@]}"; do
    full_path="$REPO_ROOT/$file"
    replace_in_file "$full_path" '"/usr/local/bin/vault-backup\.sh"' 'VaultBackupScriptPath' 'backup script'
    replace_in_file "$full_path" '"/usr/local/bin/vault-agent-health-check\.sh"' 'VaultAgentHealthCheckPath' 'health check script'
    replace_in_file "$full_path" '"/usr/bin/vault"' 'VaultBinaryPathLegacy' 'legacy binary'
done

# Config paths
echo ""
echo "=== Replacing Config Paths ==="
for file in "${FILES_TO_UPDATE[@]}"; do
    full_path="$REPO_ROOT/$file"
    replace_in_file "$full_path" '"/etc/vault\.d/vault\.hcl"' 'VaultConfigPath' 'config file'
    replace_in_file "$full_path" '"/etc/vault\.d"' 'VaultConfigDir' 'config dir'
done

# TLS paths
echo ""
echo "=== Replacing TLS Paths ==="
for file in "${FILES_TO_UPDATE[@]}"; do
    full_path="$REPO_ROOT/$file"
    replace_in_file "$full_path" '"/etc/vault\.d/tls"' 'VaultTLSDir' 'TLS dir'
    replace_in_file "$full_path" '"/etc/vault\.d/tls/vault\.crt"' 'VaultTLSCert' 'TLS cert'
    replace_in_file "$full_path" '"/etc/vault\.d/tls/vault\.key"' 'VaultTLSKey' 'TLS key'
    replace_in_file "$full_path" '"/etc/vault\.d/tls/ca\.crt"' 'VaultTLSCA' 'CA cert'
done

# Data paths
echo ""
echo "=== Replacing Data Paths ==="
for file in "${FILES_TO_UPDATE[@]}"; do
    full_path="$REPO_ROOT/$file"
    replace_in_file "$full_path" '"/opt/vault/data"' 'VaultDataDir' 'data dir'
    replace_in_file "$full_path" '"/opt/vault"' 'shared.VaultDir' 'vault base dir'
    replace_in_file "$full_path" '"/var/log/vault"' 'VaultLogsDir' 'logs dir'
done

# Systemd paths
echo ""
echo "=== Replacing Systemd Paths ==="
for file in "${FILES_TO_UPDATE[@]}"; do
    full_path="$REPO_ROOT/$file"
    replace_in_file "$full_path" '"/etc/systemd/system/vault\.service"' 'VaultServicePath' 'vault service'
    replace_in_file "$full_path" '"/etc/systemd/system/vault-agent\.service"' 'VaultAgentServicePath' 'agent service'
    replace_in_file "$full_path" '"/etc/systemd/system/vault-agent-eos\.service"' 'VaultAgentServicePath' 'agent service'
    replace_in_file "$full_path" '"/etc/systemd/system/vault-backup\.timer"' 'VaultBackupTimerPath' 'backup timer'
    replace_in_file "$full_path" '"/etc/systemd/system/vault-backup\.service"' 'VaultBackupServicePath' 'backup service'
    replace_in_file "$full_path" '"/etc/systemd/system/vault\.service\.d"' 'VaultServiceDropinDir' 'service dropin'
    replace_in_file "$full_path" '"/etc/systemd/system/vault-cert-renewal\.timer"' 'VaultCertRenewalTimerPath' 'cert renewal timer'
    replace_in_file "$full_path" '"/etc/systemd/system/vault-cert-renewal\.service"' 'VaultCertRenewalServicePath' 'cert renewal service'
done

echo ""
echo "=== Summary ==="
echo "Backup location: $BACKUP_DIR"
echo ""
echo "Files modified:"
for file in "${FILES_TO_UPDATE[@]}"; do
    full_path="$REPO_ROOT/$file"
    if [[ -f "$full_path" ]]; then
        echo "  - $file"
    fi
done

echo ""
echo "Next steps:"
echo "  1. Review changes: git diff pkg/ cmd/"
echo "  2. Verify build: go build ./cmd/"
echo "  3. Run tests: go test ./pkg/vault/..."
echo "  4. If errors, restore: cp $BACKUP_DIR/*.bak \$original_locations"
echo ""
echo "To restore all backups if needed:"
echo "  for f in $BACKUP_DIR/*.bak; do cp \$f \${f%.bak}; done"
