#!/bin/bash
# Migration script for deprecated benchmark patterns
# Converts 'for i := 0; i < b.N; i++' to 'for b.Loop()'
#
# Usage: ./scripts/migrate_benchmarks.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Benchmark Pattern Migration Tool${NC}"
echo "Converting deprecated 'for b.N' patterns to modern 'for b.Loop()'"
echo ""

# Track statistics
TOTAL_FILES=0
MODIFIED_FILES=0
TOTAL_PATTERNS=0

# Function to migrate a single file
migrate_file() {
    local file=$1
    local temp_file="${file}.tmp"

    echo -e "${YELLOW}Processing:${NC} $file"

    # Check if file contains deprecated pattern
    if ! grep -q 'for i := 0; i < b\.N; i++' "$file" && \
       ! grep -q 'for i := 0; i<b\.N; i++' "$file" && \
       ! grep -q 'for _ := range b\.N' "$file"; then
        echo "  ✓ No deprecated patterns found"
        return 0
    fi

    # Count patterns in this file
    local count=$(grep -c 'for.*b\.N' "$file" || true)
    TOTAL_PATTERNS=$((TOTAL_PATTERNS + count))

    # Create backup
    cp "$file" "${file}.bak"

    # Apply transformations
    # Pattern 1: for i := 0; i < b.N; i++ (with spaces)
    sed -i 's/for i := 0; i < b\.N; i++/for b.Loop()/g' "$file"

    # Pattern 2: for i := 0; i<b.N; i++ (without spaces)
    sed -i 's/for i := 0; i<b\.N; i++/for b.Loop()/g' "$file"

    # Pattern 3: for i:=0; i<b.N; i++ (minimal spaces)
    sed -i 's/for i:=0; i<b\.N; i++/for b.Loop()/g' "$file"

    # Pattern 4: for _ := range b.N (Go 1.22 style that's still deprecated vs b.Loop())
    sed -i 's/for _ := range b\.N/for b.Loop()/g' "$file"

    # Check if file was actually modified
    if ! diff -q "$file" "${file}.bak" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓ Migrated $count patterns${NC}"
        MODIFIED_FILES=$((MODIFIED_FILES + 1))
        rm "${file}.bak"
    else
        echo "  - No changes needed"
        mv "${file}.bak" "$file"
    fi
}

# Find all test files with benchmark functions
echo "Searching for test files with deprecated benchmark patterns..."
echo ""

# List of files from analysis
FILES=(
    "pkg/authentik/unified_client_test.go"
    "pkg/backup/operations_test.go"
    "pkg/ceph/bootstrap_test.go"
    "pkg/consul/security_test.go"
    "pkg/container/docker_test.go"
    "pkg/crypto/comprehensive_security_test.go"
    "pkg/crypto/erase_test.go"
    "pkg/crypto/input_validation_security_test.go"
    "pkg/crypto/password_security_test.go"
    "pkg/crypto/pq/mlkem_test.go"
    "pkg/crypto/redact_test.go"
    "pkg/database_management/sql_injection_test.go"
    "pkg/docker/compose_validate_test.go"
    "pkg/eos_cli/wrap_extended_test.go"
    "pkg/execute/execute_test.go"
    "pkg/execute/helpers_test.go"
    "pkg/execute/retry_test.go"
    "pkg/git/preflight_test.go"
    "pkg/hashicorp/tools_test.go"
    "pkg/hecate/terraform_integration_test.go"
    "pkg/ldap/integration_test.go"
    "pkg/ldap/security_comprehensive_test.go"
    "pkg/patterns/aie_comprehensive_test.go"
    "pkg/patterns/aie_test.go"
    "pkg/platform/firewall_test.go"
    "pkg/platform/package_lifecycle_test.go"
    "pkg/platform/platform_test.go"
    "pkg/platform/scheduler_test.go"
    "pkg/secrets/generator_test.go"
    "pkg/security/input_sanitizer_test.go"
    "pkg/security/output_test.go"
    "pkg/security/performance_test.go"
    "pkg/shared/delphi_services_test.go"
    "pkg/storage/monitor/disk_usage_improved_test.go"
    "pkg/system/service_operations_test.go"
    "pkg/system/system_config/manager_test.go"
    "pkg/ubuntu/mfa_enforced_test.go"
    "pkg/users/operations_test.go"
    "pkg/vault/auth_test.go"
    "pkg/vault/cluster_operations_integration_test.go"
    "pkg/vault/errors_test.go"
    "pkg/vault/vault_test.go"
    "pkg/wazuh/auth_integration_test.go"
    "pkg/xdg/credentials_test.go"
    "pkg/xdg/credentials_vault_test.go"
    "pkg/xdg/xdg_test.go"
)

TOTAL_FILES=${#FILES[@]}

# Process each file
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        migrate_file "$file"
    else
        echo -e "${RED}✗ File not found:${NC} $file"
    fi
done

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Migration Complete${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Statistics:"
echo "  Total files processed: $TOTAL_FILES"
echo "  Files modified: $MODIFIED_FILES"
echo "  Total patterns migrated: $TOTAL_PATTERNS"
echo ""
echo "Next steps:"
echo "  1. Run: go fmt ./..."
echo "  2. Run: go test ./pkg/... -bench=. -benchtime=100ms"
echo "  3. Verify benchmarks still work correctly"
echo "  4. Commit changes: git add -A && git commit -m 'refactor(tests): migrate to modern b.Loop() benchmark pattern'"
echo ""
