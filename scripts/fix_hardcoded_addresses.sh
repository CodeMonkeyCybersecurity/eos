#!/bin/bash
# scripts/fix_hardcoded_addresses.sh
# Replace hardcoded shared.GetInternalHostname and localhost with proper hostname resolution

set -euo pipefail

# Detect OS for sed compatibility
if [[ "$OSTYPE" == "darwin"* ]]; then
    SED_INPLACE="sed -i ''"
else
    SED_INPLACE="sed -i"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Fixing Hardcoded IP Addresses ===${NC}"
echo "This script will replace hardcoded shared.GetInternalHostname and localhost with hostname resolution"
echo "in service status and network binding code."
echo ""

# Backup directory
BACKUP_DIR="/tmp/eos-address-fix-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo -e "${YELLOW}Backup directory: $BACKUP_DIR${NC}"
echo ""

# Function to backup and replace
fix_file() {
    local file="$1"
    local pattern="$2"
    local replacement="$3"
    local description="$4"

    if [[ ! -f "$file" ]]; then
        echo -e "${RED}File not found: $file${NC}"
        return 1
    fi

    # Check if pattern exists
    if ! grep -q "$pattern" "$file"; then
        echo -e "${YELLOW}Pattern not found in $file, skipping${NC}"
        return 0
    fi

    # Backup
    cp "$file" "$BACKUP_DIR/$(basename "$file")"

    # Replace
    sed -i "s|$pattern|$replacement|g" "$file"

    echo -e "${GREEN}✓${NC} Fixed $file: $description"
}

# Fix servicestatus/consul.go - Health check endpoint
echo "Fixing pkg/servicestatus/consul.go..."
fix_file "pkg/servicestatus/consul.go" \
    'fmt.Sprintf("http://shared.GetInternalHostname:%d/v1/status/leader", shared.PortConsul)' \
    'fmt.Sprintf("http://%s:%d/v1/status/leader", hostname, shared.PortConsul)' \
    "Use hostname for Consul health check"

# Fix servicestatus/vault.go - Network endpoint display
echo "Fixing pkg/servicestatus/vault.go..."
# Note: Vault's shared.GetInternalHostname in health checks should stay, but network info should use hostname
# We'll update the Address field to use hostname for consistency with Consul
sed -i 's/Address:  "shared.GetInternalHostname",$/Address:  shared.GetInternalHostname(),/' pkg/servicestatus/vault.go
echo -e "${GREEN}✓${NC} Fixed pkg/servicestatus/vault.go: Use GetInternalHostname() for network endpoint"

# Fix debug/vault/diagnostics.go - Health URL
echo "Fixing pkg/debug/vault/diagnostics.go..."
fix_file "pkg/debug/vault/diagnostics.go" \
    'healthURL := fmt.Sprintf("http://shared.GetInternalHostname:%d/v1/sys/health", shared.PortVault)' \
    'healthURL := fmt.Sprintf("http://%s:%d/v1/sys/health", shared.GetInternalHostname(), shared.PortVault)' \
    "Use GetInternalHostname() for health URL"

# Fix vault/install.go - API and Cluster addresses
echo "Fixing pkg/vault/install.go..."
sed -i 's|fmt.Sprintf("%s://shared.GetInternalHostname:%d", protocol, shared.PortVault)|fmt.Sprintf("%s://%s:%d", protocol, shared.GetInternalHostname(), shared.PortVault)|' pkg/vault/install.go
echo -e "${GREEN}✓${NC} Fixed pkg/vault/install.go: Use GetInternalHostname() for API/cluster addresses"

# Fix consul address defaults in various packages
echo "Fixing Consul address defaults..."

# terraform/providers.go
if grep -q 'consulAddr = "http://shared.GetInternalHostname:8500"' pkg/terraform/providers.go; then
    sed -i 's|consulAddr = "http://shared.GetInternalHostname:8500"|consulAddr = fmt.Sprintf("http://%s:%d", shared.GetInternalHostname(), shared.PortConsul)|' pkg/terraform/providers.go
    echo -e "${GREEN}✓${NC} Fixed pkg/terraform/providers.go"
fi

# terraform/executor.go
if grep -q 'vaultAddr = fmt.Sprintf("http://shared.GetInternalHostname:%d"' pkg/terraform/executor.go; then
    sed -i 's|vaultAddr = fmt.Sprintf("http://shared.GetInternalHostname:%d", shared.PortVault)|vaultAddr = fmt.Sprintf("http://%s:%d", shared.GetInternalHostname(), shared.PortVault)|' pkg/terraform/executor.go
    echo -e "${GREEN}✓${NC} Fixed pkg/terraform/executor.go"
fi

# terraform/nomad_consul.go
if grep -q 'address = "shared.GetInternalHostname:8500"' pkg/terraform/nomad_consul.go; then
    sed -i 's|address = "shared.GetInternalHostname:8500"|address = "{{ GetInternalHostname }}:{{ .PortConsul }}"|' pkg/terraform/nomad_consul.go
    echo -e "${GREEN}✓${NC} Fixed pkg/terraform/nomad_consul.go (template)"
fi

# Fix create commands that hardcode localhost for Vault/Consul addresses
echo "Fixing create command defaults..."

# cmd/create/secrets_terraform.go
if grep -q 'vaultConfig.VaultAddr = fmt.Sprintf("https://shared.GetInternalHostname:%d"' cmd/create/secrets_terraform.go; then
    sed -i 's|vaultConfig.VaultAddr = fmt.Sprintf("https://shared.GetInternalHostname:%d", shared.PortVault)|vaultConfig.VaultAddr = fmt.Sprintf("https://%s:%d", shared.GetInternalHostname(), shared.PortVault)|g' cmd/create/secrets_terraform.go
    echo -e "${GREEN}✓${NC} Fixed cmd/create/secrets_terraform.go"
fi

# cmd/create/secrets_terraform_generators.go
if grep -q 'vaultAddr = fmt.Sprintf("https://shared.GetInternalHostname:%d"' cmd/create/secrets_terraform_generators.go; then
    sed -i 's|vaultAddr = fmt.Sprintf("https://shared.GetInternalHostname:%d", shared.PortVault)|vaultAddr = fmt.Sprintf("https://%s:%d", shared.GetInternalHostname(), shared.PortVault)|g' cmd/create/secrets_terraform_generators.go
    echo -e "${GREEN}✓${NC} Fixed cmd/create/secrets_terraform_generators.go"
fi

# cmd/create/hashicorp.go - Keep shared.GetInternalHostname as DEFAULT FLAG VALUE (user can override)
# But note in help text that hostname resolution is available
echo -e "${YELLOW}Note: cmd/create/hashicorp.go flag defaults kept as shared.GetInternalHostname (user configurable)${NC}"

echo ""
echo -e "${GREEN}=== Summary ===${NC}"
echo "Files have been updated to use hostname resolution instead of hardcoded shared.GetInternalHostname"
echo "Backups saved to: $BACKUP_DIR"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review changes: git diff"
echo "2. Test compilation: go build -o /tmp/eos-build ./cmd/"
echo "3. Run tests: go test -v ./pkg/servicestatus/..."
echo "4. If issues occur, restore from: $BACKUP_DIR"
echo ""
echo -e "${GREEN}Note:${NC} Some localhost references are intentional (security filters, tests, examples)"
echo "Those have been preserved."
