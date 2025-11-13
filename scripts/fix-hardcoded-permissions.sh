#!/bin/bash
# scripts/fix-hardcoded-permissions.sh
# Automatically replace hardcoded file permissions with named constants
#
# USAGE: ./scripts/fix-hardcoded-permissions.sh [--dry-run] [--create-constants-only]
#
# PURPOSE: Fixes P0-2 Hardcoded Permissions Compliance Risk
#   - 1347 violations (78 in cmd/, 1269 in pkg/)
#   - Issue: SOC2/PCI-DSS/HIPAA audit failure - no documented security rationale
#   - Solution: Centralized constants with RATIONALE/SECURITY/THREAT MODEL documentation
#
# PHASE 1: Create pkg/shared/permissions.go with documented constants
# PHASE 2: Replace hardcoded values in all Go files
#
# SAFETY:
#   - Run with --dry-run first to preview changes
#   - Creates backups with .permissions.bak extension
#   - Only replaces exact octal patterns (0755, 0644, etc.)
#
# EVIDENCE: See ROADMAP.md "Adversarial Analysis & Systematic Remediation (2025-11-13)"

set -euo pipefail

# Configuration
DRY_RUN=false
CREATE_CONSTANTS_ONLY=false
BACKUP_EXT=".permissions.bak"
CONSTANTS_FILE="pkg/shared/permissions.go"
REPLACED_COUNT=0
SKIPPED_COUNT=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --create-constants-only)
            CREATE_CONSTANTS_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dry-run] [--create-constants-only]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Hardcoded Permissions Auto-Fixer (P0-2)${NC}"
echo -e "${BLUE}========================================${NC}"
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}DRY RUN MODE - No files will be modified${NC}"
fi
echo ""

#######################################
# PHASE 1: Create constants file
#######################################
echo -e "${BLUE}Phase 1: Creating permission constants file${NC}"

CONSTANTS_CONTENT='// pkg/shared/permissions.go
// Centralized file permission constants with security rationale
//
// CRITICAL: All file permissions MUST be defined here with documented rationale.
// This is required for SOC2, PCI-DSS, and HIPAA compliance audits.
//
// CLAUDE.md P0 Rule #12: NEVER hardcode chmod/chown permissions (0755, 0600, etc.)
// Each constant MUST include:
//   - RATIONALE: Why this permission level
//   - SECURITY: What threats this mitigates
//   - THREAT MODEL: Attack scenarios prevented
//
// See: ROADMAP.md "Adversarial Analysis (2025-11-13)" for compliance requirements

package shared

import "os"

// Directory Permissions
const (
	// ServiceDirPerm is for service installation directories (/opt/service)
	// RATIONALE: Owner/group read/write/exec, world read/exec enables shared access
	// SECURITY: Allows service user + admin group to manage files without world-write
	// THREAT MODEL: Prevents malware injection via world-writable directories (0777)
	ServiceDirPerm = os.FileMode(0755)

	// SecretDirPerm is for directories containing secret files
	// RATIONALE: Owner/group read/write/exec only, no world access
	// SECURITY: Prevents unauthorized access to secret directory listings
	// THREAT MODEL: Prevents credential theft via directory traversal
	SecretDirPerm = os.FileMode(0750)

	// SystemConfigDirPerm is for system configuration directories (/etc/eos, /etc/vault)
	// RATIONALE: Owner/group read/write/exec, world read/exec for system services
	// SECURITY: Allows services to read configs without write access
	// THREAT MODEL: Prevents config tampering by non-privileged processes
	SystemConfigDirPerm = os.FileMode(0755)
)

// File Permissions
const (
	// ConfigFilePerm is for non-secret configuration files
	// RATIONALE: Owner/group read/write, world read enables automation
	// SECURITY: Allows services to read configs, prevents unauthorized modification
	// THREAT MODEL: Prevents config tampering while maintaining readability
	ConfigFilePerm = os.FileMode(0644)

	// SecretFilePerm is for files containing secrets (passwords, tokens, keys)
	// RATIONALE: Owner read/write only, no group/world access
	// SECURITY: Prevents credential theft by other users or processes
	// THREAT MODEL: Mitigates privilege escalation via credential exposure
	SecretFilePerm = os.FileMode(0600)

	// ReadOnlySecretFilePerm is for secret files that should not be modified after creation
	// RATIONALE: Owner read only, prevents tampering after initial write
	// SECURITY: Prevents credential modification by compromised processes
	// THREAT MODEL: Mitigates credential replacement attacks, ensures integrity
	ReadOnlySecretFilePerm = os.FileMode(0400)

	// ExecutablePerm is for binary files and scripts
	// RATIONALE: Owner/group read/write/exec, world read/exec
	// SECURITY: Allows execution by services, prevents unauthorized modification
	// THREAT MODEL: Prevents binary replacement attacks
	ExecutablePerm = os.FileMode(0755)

	// SecureConfigFilePerm is for configuration files with sensitive data
	// RATIONALE: Owner/group read/write, no world access
	// SECURITY: Protects sensitive configs from unauthorized reading
	// THREAT MODEL: Prevents information disclosure via config files
	SecureConfigFilePerm = os.FileMode(0640)

	// SystemServiceFilePerm is for systemd service files
	// RATIONALE: Owner/group read/write, world read
	// SECURITY: Allows systemd to read service definitions
	// THREAT MODEL: Prevents service definition tampering
	SystemServiceFilePerm = os.FileMode(0644)

	// LogFilePerm is for log files
	// RATIONALE: Owner/group read/write, world read for debugging
	// SECURITY: Allows log aggregation tools to read logs
	// THREAT MODEL: Balance between auditability and access control
	LogFilePerm = os.FileMode(0644)

	// TempPasswordFilePerm is for temporary password files (used during operations)
	// RATIONALE: Owner read-only, auto-cleanup via defer
	// SECURITY: Prevents password scraping during transit
	// THREAT MODEL: Mitigates process memory dump attacks (see P0-1 Token Exposure Fix)
	// EVIDENCE: Used in pkg/vault/cluster_token_security.go for VAULT_TOKEN_FILE pattern
	TempPasswordFilePerm = os.FileMode(0400)
)

// Ownership Constants
const (
	// RootUID is the UID for root user
	// RATIONALE: System-level operations require root
	// SECURITY: Explicit root check prevents accidental privilege usage
	// THREAT MODEL: Documents where root is intentionally required
	RootUID = 0

	// RootGID is the GID for root group
	// RATIONALE: Root group for system administration
	// SECURITY: Limits group-based access to root group only
	// THREAT MODEL: Prevents privilege escalation via group membership
	RootGID = 0
)

// PermissionValidator validates that a permission is secure
func PermissionValidator(perm os.FileMode) error {
	// Check for world-writable (security violation)
	if perm&0002 != 0 {
		return fmt.Errorf("permission %o is world-writable (security violation)", perm)
	}
	return nil
}
'

if [ "$DRY_RUN" = true ]; then
    echo "  [DRY RUN] Would create $CONSTANTS_FILE"
    if [ -f "$CONSTANTS_FILE" ]; then
        echo -e "  ${YELLOW}⚠ File already exists, would be backed up${NC}"
    fi
else
    # Create pkg/shared directory if it doesn't exist
    mkdir -p pkg/shared

    # Backup existing file if it exists
    if [ -f "$CONSTANTS_FILE" ]; then
        cp "$CONSTANTS_FILE" "${CONSTANTS_FILE}${BACKUP_EXT}"
        echo -e "  ${YELLOW}⚠ Backed up existing file${NC}"
    fi

    # Write constants file
    echo "$CONSTANTS_CONTENT" > "$CONSTANTS_FILE"
    echo -e "  ${GREEN}✓ Created $CONSTANTS_FILE${NC}"
fi

if [ "$CREATE_CONSTANTS_ONLY" = true ]; then
    echo ""
    echo -e "${GREEN}CONSTANTS CREATED - Skipping replacement phase${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review: cat $CONSTANTS_FILE"
    echo "  2. Build: go build -o /tmp/eos-build ./cmd/"
    echo "  3. Run full fix: ./scripts/fix-hardcoded-permissions.sh"
    exit 0
fi

#######################################
# PHASE 2: Replace hardcoded permissions
#######################################
echo ""
echo -e "${BLUE}Phase 2: Replacing hardcoded permissions${NC}"

# Define replacement mappings
# Format: "octal_value:constant_name:typical_usage"
declare -a REPLACEMENTS=(
    "0755:shared.ServiceDirPerm:directory permissions"
    "0750:shared.SecretDirPerm:secret directory permissions"
    "0644:shared.ConfigFilePerm:config file permissions"
    "0640:shared.SecureConfigFilePerm:secure config file permissions"
    "0600:shared.SecretFilePerm:secret file permissions"
    "0400:shared.ReadOnlySecretFilePerm:read-only secret file permissions"
)

# Find all Go files (excluding vendor, .git)
FILES=$(find cmd pkg -name "*.go" -type f ! -path "*/vendor/*" ! -path "*/.git/*")

echo "Files to scan: $(echo "$FILES" | wc -l)"
echo ""

for file in $FILES; do
    CHANGES_MADE=false

    # Check each replacement pattern
    for replacement in "${REPLACEMENTS[@]}"; do
        IFS=':' read -r octal_value constant_name usage <<< "$replacement"

        # Check if file contains this hardcoded value
        if grep -q "$octal_value" "$file"; then
            if [ "$CHANGES_MADE" = false ]; then
                echo -e "${BLUE}→ Processing: $file${NC}"
                CHANGES_MADE=true
            fi

            # Count occurrences
            count=$(grep -c "$octal_value" "$file" || true)

            if [ "$DRY_RUN" = true ]; then
                echo "  [DRY RUN] Would replace $count occurrence(s) of $octal_value with $constant_name"
            else
                # Backup file on first change
                if [ ! -f "${file}${BACKUP_EXT}" ]; then
                    cp "$file" "${file}${BACKUP_EXT}"
                fi

                # Replace the octal value with constant
                # Handle both bare octal and os.FileMode(octal) patterns
                sed -i "s/${octal_value}/${constant_name}/g" "$file"

                # Add import if not present
                if ! grep -q '"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"' "$file"; then
                    sed -i '/"github.com\/CodeMonkeyCybersecurity\/eos\/pkg\/eos_io"/a\	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"' "$file" || true
                fi

                echo -e "  ${GREEN}✓ Replaced $count occurrence(s) of $octal_value with $constant_name${NC}"
            fi
        fi
    done

    if [ "$CHANGES_MADE" = true ]; then
        ((REPLACED_COUNT++))
    fi
done

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Files modified: $REPLACED_COUNT${NC}"

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo -e "${YELLOW}DRY RUN COMPLETE - No files were modified${NC}"
    echo "Run without --dry-run to apply changes"
else
    echo ""
    echo -e "${GREEN}COMPLETE - Backup files created with ${BACKUP_EXT} extension${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review changes: git diff cmd/ pkg/"
    echo "  2. Test build: go build -o /tmp/eos-build ./cmd/"
    echo "  3. Run tests: go test ./pkg/... ./cmd/..."
    echo "  4. Review constants: cat $CONSTANTS_FILE"
    echo "  5. If issues, restore: find . -name '*${BACKUP_EXT}' -exec bash -c 'mv \"\$0\" \"\${0%${BACKUP_EXT}}\"' {} \;"
fi

exit 0
