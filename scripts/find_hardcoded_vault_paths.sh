#!/usr/bin/env bash
# find_hardcoded_vault_paths.sh
# Find all hardcoded Vault-related paths in the codebase

set -euo pipefail

REPO_ROOT="/Users/henry/Dev/eos"
OUTPUT_FILE="/tmp/vault_hardcoded_paths.txt"

echo "Scanning for hardcoded Vault paths..."
echo "Report will be saved to: $OUTPUT_FILE"
echo ""

{
    echo "================================"
    echo "HARDCODED VAULT PATHS REPORT"
    echo "Generated: $(date)"
    echo "================================"
    echo ""

    echo "=== BINARY PATHS ==="
    echo "Pattern: /usr/local/bin/vault or /usr/bin/vault"
    grep -rn 'VaultBinaryPath\|VaultBinaryPath' "$REPO_ROOT" \
        --include="*.go" \
        --exclude-dir=".git" \
        --exclude-dir="vendor" | head -50
    echo ""

    echo "=== CONFIG DIRECTORY ==="
    echo "Pattern: /etc/vault.d"
    grep -rn '"/etc/vault\.d' "$REPO_ROOT" \
        --include="*.go" \
        --exclude-dir=".git" \
        --exclude-dir="vendor" | head -50
    echo ""

    echo "=== TLS PATHS ==="
    echo "Pattern: /etc/vault.d/tls"
    grep -rn '"/etc/vault\.d/tls' "$REPO_ROOT" \
        --include="*.go" \
        --exclude-dir=".git" \
        --exclude-dir="vendor" | head -30
    echo ""

    echo "=== DATA PATHS ==="
    echo "Pattern: /opt/vault"
    grep -rn '"/opt/vault' "$REPO_ROOT" \
        --include="*.go" \
        --exclude-dir=".git" \
        --exclude-dir="vendor" | head -30
    echo ""

    echo "=== SCRIPT PATHS ==="
    echo "Pattern: /usr/local/bin/vault-*.sh"
    grep -rn '"/usr/local/bin/vault-.*\.sh"' "$REPO_ROOT" \
        --include="*.go" \
        --exclude-dir=".git" \
        --exclude-dir="vendor" | head -30
    echo ""

    echo "=== IP ADDRESSES (shared.GetInternalHostname / 0.0.0.0) ==="
    echo "Pattern: hardcoded shared.GetInternalHostname or 0.0.0.0 in vault package"
    grep -rn '"127\.0\.0\.1"\|"0\.0\.0\.0"' "$REPO_ROOT/pkg/vault" \
        --include="*.go" \
        --exclude-dir=".git" | head -40
    echo ""

    echo "=== PORT NUMBERS (8179, 8180) ==="
    echo "Pattern: hardcoded port numbers"
    grep -rn ':8179\|:8180' "$REPO_ROOT/pkg/vault" \
        --include="*.go" \
        --exclude-dir=".git" | head -30
    echo ""

    echo "=== SYSTEMD PATHS ==="
    echo "Pattern: /etc/systemd/system/vault"
    grep -rn '"/etc/systemd/system/vault' "$REPO_ROOT" \
        --include="*.go" \
        --exclude-dir=".git" \
        --exclude-dir="vendor" | head -20
    echo ""

    echo "================================"
    echo "SUMMARY"
    echo "================================"
    echo ""
    echo "Files to update (non-constants.go, non-types.go):"
    {
        grep -rl 'VaultBinaryPath\|VaultBinaryPath' "$REPO_ROOT" --include="*.go" --exclude-dir=".git" --exclude-dir="vendor"
        grep -rl '"/etc/vault\.d' "$REPO_ROOT" --include="*.go" --exclude-dir=".git" --exclude-dir="vendor"
        grep -rl '"/opt/vault' "$REPO_ROOT" --include="*.go" --exclude-dir=".git" --exclude-dir="vendor"
    } | sort -u | grep -v "constants.go" | grep -v "types.go" || echo "None found"

    echo ""
    echo "================================"
    echo "REPLACEMENT CONSTANTS AVAILABLE"
    echo "================================"
    echo ""
    echo "In pkg/vault/constants.go:"
    echo "  VaultBinaryPath           = \"/usr/local/bin/vault\""
    echo "  VaultBinaryPathLegacy     = \"/usr/bin/vault\""
    echo "  VaultConfigDir            = \"/etc/vault.d\""
    echo "  VaultConfigPath           = \"/etc/vault.d/vault.hcl\""
    echo "  VaultTLSDir               = \"/etc/vault.d/tls\""
    echo "  VaultTLSCert              = \"/etc/vault.d/tls/vault.crt\""
    echo "  VaultTLSKey               = \"/etc/vault.d/tls/vault.key\""
    echo "  VaultDataDir              = \"/opt/vault/data\""
    echo "  VaultLogsDir              = \"/var/log/vault\""
    echo "  VaultBackupScriptPath     = \"/usr/local/bin/vault-backup.sh\""
    echo "  VaultAgentHealthCheckPath = \"/usr/local/bin/vault-agent-health-check.sh\""
    echo "  VaultSnapshotScriptPath   = \"/usr/local/bin/vault-snapshot.sh\""
    echo "  VaultServicePath          = \"/etc/systemd/system/vault.service\""
    echo "  VaultAgentServicePath     = \"/etc/systemd/system/vault-agent-eos.service\""
    echo ""
    echo "  VaultListenAddr           = \"0.0.0.0\""
    echo "  VaultClientAddr           = \"shared.GetInternalHostname\""
    echo "  VaultDefaultPort          = 8179"
    echo "  VaultClusterPort          = 8180"
    echo ""
} | tee "$OUTPUT_FILE"

echo ""
echo "Report saved to: $OUTPUT_FILE"
echo ""
echo "To review: cat $OUTPUT_FILE"
