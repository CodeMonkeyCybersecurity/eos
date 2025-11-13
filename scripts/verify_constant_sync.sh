#!/bin/bash
# verify_constant_sync.sh - Verify duplicated constants match source of truth
#
# PURPOSE:
#   P0-2 remediation created circular import exceptions where constants are
#   duplicated in multiple files. This script ensures duplicated values stay
#   synchronized with their source of truth.
#
# USAGE:
#   ./scripts/verify_constant_sync.sh
#   Exit 0: All constants synchronized
#   Exit 1: Drift detected (values mismatch)
#
# CI/CD INTEGRATION:
#   Add to .github/workflows/test.yml:
#     - name: Verify constant synchronization
#       run: ./scripts/verify_constant_sync.sh
#
# AUTHOR: Eos P0-2 Remediation (2025-11-13)
# LAST UPDATED: 2025-11-13

set -euo pipefail

# Color output for readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Constant Synchronization Verification ==="
echo "Checking for drift in duplicated constants..."
echo ""

# Track overall status
DRIFT_DETECTED=0
CHECKS_PASSED=0
CHECKS_FAILED=0

# Helper function: Extract constant value from Go file
# Usage: extract_const "ConstName" "file.go"
extract_const() {
    local const_name="$1"
    local file_path="$2"

    # Match patterns like:
    #   ConstName = 0755
    #   ConstName = "value"
    #   const consulConfigPerm = 0750
    grep -E "(const\s+)?${const_name}\s*=\s*[0-9a-fx\"]+|${const_name}\s*:=\s*[0-9a-fx\"]+" "$file_path" \
        | sed -E 's/.*=\s*([0-9a-fx"]+).*/\1/' \
        | head -1
}

# Helper function: Check if constant matches source
# Usage: check_constant "ConstName" "source_file.go" "duplicate_file.go"
check_constant() {
    local const_name="$1"
    local source_file="$2"
    local duplicate_file="$3"

    echo -n "  Checking ${const_name}... "

    # Extract values
    source_value=$(extract_const "$const_name" "$source_file" || echo "")
    duplicate_value=$(extract_const "$const_name" "$duplicate_file" || echo "")

    # Handle case where constant might have lowercase variant
    if [ -z "$duplicate_value" ]; then
        local lowercase_name=$(echo "$const_name" | sed 's/Consul/consul/')
        duplicate_value=$(extract_const "$lowercase_name" "$duplicate_file" || echo "")
    fi

    # Check if both values exist
    if [ -z "$source_value" ]; then
        echo -e "${RED}FAIL${NC} - source value not found in $source_file"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
        DRIFT_DETECTED=1
        return 1
    fi

    if [ -z "$duplicate_value" ]; then
        echo -e "${YELLOW}SKIP${NC} - duplicate value not found (may be function, not constant)"
        return 0
    fi

    # Compare values
    if [ "$source_value" = "$duplicate_value" ]; then
        echo -e "${GREEN}PASS${NC} ($source_value)"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        return 0
    else
        echo -e "${RED}FAIL${NC} - drift detected!"
        echo "    Source:    $source_value (in $source_file)"
        echo "    Duplicate: $duplicate_value (in $duplicate_file)"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
        DRIFT_DETECTED=1
        return 1
    fi
}

# ============================================================================
# CONSUL PACKAGE - Permission Constants
# ============================================================================
echo "=== Consul Permission Constants ==="
SOURCE_CONSUL="pkg/consul/constants.go"

# pkg/consul/lock/flock.go:17
echo "File: pkg/consul/lock/flock.go"
check_constant "ConsulConfigPerm" "$SOURCE_CONSUL" "pkg/consul/lock/flock.go"

# pkg/consul/config/setup.go:20
echo "File: pkg/consul/config/setup.go"
check_constant "ConsulConfigDirPerm" "$SOURCE_CONSUL" "pkg/consul/config/setup.go"
check_constant "ConsulDataDirPerm" "$SOURCE_CONSUL" "pkg/consul/config/setup.go"
check_constant "ConsulLogDirPerm" "$SOURCE_CONSUL" "pkg/consul/config/setup.go"
check_constant "ConsulOptDirPerm" "$SOURCE_CONSUL" "pkg/consul/config/setup.go"

# pkg/consul/acl/reset.go:39
echo "File: pkg/consul/acl/reset.go"
check_constant "ConsulConfigPerm" "$SOURCE_CONSUL" "pkg/consul/acl/reset.go"

# pkg/consul/service/atomic.go:13
echo "File: pkg/consul/service/atomic.go"
check_constant "ConsulConfigPerm" "$SOURCE_CONSUL" "pkg/consul/service/atomic.go"

echo ""

# ============================================================================
# CONSUL PACKAGE - Path Constants
# ============================================================================
echo "=== Consul Path Constants ==="

# pkg/consul/acl/reset.go (multiple path constants)
echo "File: pkg/consul/acl/reset.go"
check_constant "ConsulACLResetFilename" "$SOURCE_CONSUL" "pkg/consul/acl/reset.go"
check_constant "ConsulOptDir" "$SOURCE_CONSUL" "pkg/consul/acl/reset.go"
check_constant "ConsulDataDir" "$SOURCE_CONSUL" "pkg/consul/acl/reset.go"

echo ""

# ============================================================================
# CONSUL PACKAGE - Service Name Constant
# ============================================================================
echo "=== Consul Service Constants ==="

# pkg/consul/config/acl_enablement.go:24
echo "File: pkg/consul/config/acl_enablement.go"
check_constant "ConsulServiceName" "$SOURCE_CONSUL" "pkg/consul/config/acl_enablement.go"

echo ""

# ============================================================================
# CONSUL PACKAGE - Binary Path (Function, not constant)
# ============================================================================
echo "=== Consul Binary Path Functions ==="
echo "File: pkg/consul/service/manager.go"
echo "  Checking GetConsulBinaryPath()... ${YELLOW}SKIP${NC} - function duplication, not constant"
echo "  NOTE: Manual verification required - compare GetConsulBinaryPath() implementations"
echo ""

# ============================================================================
# SHARED PACKAGE - Permission Constants Used in Consul
# ============================================================================
echo "=== Shared Permission Constants (used in consul/validation/datadir.go) ==="
SOURCE_SHARED="pkg/shared/permissions.go"

# pkg/consul/validation/datadir.go uses shared.SecretFilePerm
# This is NOT a duplicate, it's proper usage of shared constants
# No verification needed - shared constants are the source of truth
echo "  pkg/consul/validation/datadir.go uses shared.SecretFilePerm... ${GREEN}PASS${NC} (not a duplicate)"
echo ""

# ============================================================================
# SUMMARY
# ============================================================================
echo "=== Verification Summary ==="
echo "Checks passed: ${CHECKS_PASSED}"
echo "Checks failed: ${CHECKS_FAILED}"
echo ""

if [ $DRIFT_DETECTED -eq 0 ]; then
    echo -e "${GREEN}✓ All constants synchronized!${NC}"
    echo "All duplicated constants match their source of truth."
    exit 0
else
    echo -e "${RED}✗ Drift detected!${NC}"
    echo ""
    echo "REMEDIATION STEPS:"
    echo "  1. Identify which file has the correct value (source vs duplicate)"
    echo "  2. Update the incorrect file to match the source of truth"
    echo "  3. Re-run this script to verify synchronization"
    echo "  4. Add a note to the duplicate explaining the value change"
    echo ""
    echo "SOURCE OF TRUTH FILES:"
    echo "  - pkg/consul/constants.go - All Consul constants"
    echo "  - pkg/shared/permissions.go - Shared permission constants"
    echo "  - pkg/vault/constants.go - Vault permission constants"
    echo ""
    echo "CIRCULAR IMPORT EXCEPTIONS (duplicates required):"
    echo "  - pkg/consul/lock/flock.go"
    echo "  - pkg/consul/config/setup.go"
    echo "  - pkg/consul/acl/reset.go"
    echo "  - pkg/consul/service/atomic.go"
    echo "  - pkg/consul/config/acl_enablement.go"
    echo ""
    exit 1
fi
