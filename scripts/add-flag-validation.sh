#!/bin/bash
# scripts/add-flag-validation.sh
# Automatically add ValidateNoFlagLikeArgs() to commands with positional arguments
#
# USAGE: ./scripts/add-flag-validation.sh [--dry-run] [--file path/to/file.go]
#
# PURPOSE: Fixes P0-1 Flag Bypass Vulnerability
#   - Only 6 of 363 commands currently protected (1.7%)
#   - Attack: `eos delete env production -- --force` bypasses --force flag
#   - Solution: Add verify.ValidateNoFlagLikeArgs(args) to all commands with positional args
#
# SAFETY:
#   - Run with --dry-run first to preview changes
#   - Creates backups with .bak extension
#   - Only modifies files with cobra.ExactArgs/MaximumNArgs/MinimumNArgs
#
# EVIDENCE: See ROADMAP.md "Adversarial Analysis & Systematic Remediation (2025-11-13)"

set -euo pipefail

# Configuration
DRY_RUN=false
SINGLE_FILE=""
BACKUP_EXT=".bak"
ADDED_COUNT=0
SKIPPED_COUNT=0
ERROR_COUNT=0

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
        --file)
            SINGLE_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dry-run] [--file path/to/file.go]"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Flag Validation Auto-Fixer (P0-1)${NC}"
echo -e "${BLUE}========================================${NC}"
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}DRY RUN MODE - No files will be modified${NC}"
fi
echo ""

# Find files to process
if [ -n "$SINGLE_FILE" ]; then
    FILES="$SINGLE_FILE"
else
    # Find all Go files in cmd/ that have ExactArgs/MaximumNArgs/MinimumNArgs
    FILES=$(grep -rl "cobra\.ExactArgs\|cobra\.MaximumNArgs\|cobra\.MinimumNArgs" cmd/ --include="*.go" || true)
fi

if [ -z "$FILES" ]; then
    echo -e "${YELLOW}No files found with positional argument validators${NC}"
    exit 0
fi

echo "Files to check: $(echo "$FILES" | wc -w)"
echo ""

# Process each file
for file in $FILES; do
    # Skip if file doesn't exist
    if [ ! -f "$file" ]; then
        echo -e "${YELLOW}⊘ Skipping (not found): $file${NC}"
        ((SKIPPED_COUNT++))
        continue
    fi

    # Check if file already has ValidateNoFlagLikeArgs
    if grep -q "ValidateNoFlagLikeArgs" "$file"; then
        echo -e "${GREEN}✓ Already protected: $file${NC}"
        ((SKIPPED_COUNT++))
        continue
    fi

    # Check if file has positional argument validators
    if ! grep -q "cobra\.ExactArgs\|cobra\.MaximumNArgs\|cobra\.MinimumNArgs" "$file"; then
        echo -e "${YELLOW}⊘ No positional args: $file${NC}"
        ((SKIPPED_COUNT++))
        continue
    fi

    echo -e "${BLUE}→ Processing: $file${NC}"

    # Backup file
    if [ "$DRY_RUN" = false ]; then
        cp "$file" "${file}${BACKUP_EXT}"
    fi

    # Check if verify package is already imported
    HAS_VERIFY_IMPORT=$(grep -c '"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"' "$file" || true)

    # Find the RunE function and add validation
    # Pattern: Look for "RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {"
    # After the logger line, insert the validation

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would add ValidateNoFlagLikeArgs() call"
        if [ "$HAS_VERIFY_IMPORT" -eq 0 ]; then
            echo "  [DRY RUN] Would add verify package import"
        fi
        ((ADDED_COUNT++))
    else
        # Add import if missing
        if [ "$HAS_VERIFY_IMPORT" -eq 0 ]; then
            # Find the import block and add verify import
            # This is a simplified approach - may need manual review
            sed -i '/"github.com\/CodeMonkeyCybersecurity\/eos\/pkg\/eos_io"/a\	"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"' "$file"
            echo "  ✓ Added verify package import"
        fi

        # Add validation after logger initialization
        # This uses awk to find the pattern and insert validation
        awk '
        /logger := otelzap\.Ctx\(rc\.Ctx\)/ {
            print
            print ""
            print "\t\t// CRITICAL: Detect flag-like args (P0-1 fix)"
            print "\t\tif err := verify.ValidateNoFlagLikeArgs(args); err != nil {"
            print "\t\t\treturn err"
            print "\t\t}"
            next
        }
        { print }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"

        echo -e "  ${GREEN}✓ Added flag validation${NC}"
        ((ADDED_COUNT++))
    fi
done

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Files modified: $ADDED_COUNT${NC}"
echo -e "${YELLOW}Files skipped: $SKIPPED_COUNT${NC}"
if [ "$ERROR_COUNT" -gt 0 ]; then
    echo -e "${RED}Errors: $ERROR_COUNT${NC}"
fi

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo -e "${YELLOW}DRY RUN COMPLETE - No files were modified${NC}"
    echo "Run without --dry-run to apply changes"
else
    echo ""
    echo -e "${GREEN}COMPLETE - Backup files created with ${BACKUP_EXT} extension${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review changes: git diff cmd/"
    echo "  2. Test build: go build -o /tmp/eos-build ./cmd/"
    echo "  3. Run tests: go test ./cmd/..."
    echo "  4. If issues, restore: for f in cmd/**/*${BACKUP_EXT}; do mv \$f \${f%${BACKUP_EXT}}; done"
fi

exit 0
