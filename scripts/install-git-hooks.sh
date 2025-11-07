#!/bin/bash
# Install Git hooks for Eos development
#
# This script installs pre-commit hooks that enforce code quality standards
# as defined in CLAUDE.md P0 Rule #10.
#
# Usage: ./scripts/install-git-hooks.sh

set -e

# Get the repository root
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$REPO_ROOT" ]; then
    echo "Error: Not in a git repository"
    exit 1
fi

cd "$REPO_ROOT"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🔧 Installing Git hooks for Eos"
echo ""

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Check if pre-commit already exists
if [ -f .git/hooks/pre-commit ]; then
    echo -e "${YELLOW}⚠${NC}  Pre-commit hook already exists"
    read -p "Overwrite? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Skipping pre-commit hook installation"
        exit 0
    fi
fi

# Create pre-commit hook
cat > .git/hooks/pre-commit << 'HOOK_EOF'
#!/bin/bash
# Eos Pre-Commit Hook
# Enforces CLAUDE.md P0 Rule #10: Zero tolerance for compile-time errors
#
# This hook runs before every commit to ensure:
# 1. Code compiles successfully
# 2. go vet passes on pkg/ and cmd/
# 3. gofmt reports no formatting issues
#
# To bypass (NOT RECOMMENDED): git commit --no-verify

set -e

echo "🔍 Pre-commit validation (CLAUDE.md P0 Rule #10)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Get the repository root
REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track if any check failed
FAILED=0

# Check 1: Go build
echo ""
echo "📦 Check 1/4: Building project..."
if go build -o /tmp/eos-build ./cmd/ 2>&1; then
    echo -e "${GREEN}✓${NC} Build successful"
    rm -f /tmp/eos-build
else
    echo -e "${RED}✗${NC} Build failed"
    echo ""
    echo "Fix the build errors above before committing."
    FAILED=1
fi

# Check 2: go vet on pkg/
echo ""
echo "🔎 Check 2/4: Running 'go vet ./pkg/...'"
if go vet ./pkg/... 2>&1; then
    echo -e "${GREEN}✓${NC} go vet ./pkg/... passed"
else
    echo -e "${RED}✗${NC} go vet ./pkg/... failed"
    FAILED=1
fi

# Check 3: go vet on cmd/
echo ""
echo "🔎 Check 3/4: Running 'go vet ./cmd/...'"
if go vet ./cmd/... 2>&1; then
    echo -e "${GREEN}✓${NC} go vet ./cmd/... passed"
else
    echo -e "${RED}✗${NC} go vet ./cmd/... failed"
    FAILED=1
fi

# Check 4: gofmt
echo ""
echo "📐 Check 4/4: Checking code formatting..."
UNFORMATTED=$(gofmt -l . 2>&1 | grep -v vendor || true)
if [ -z "$UNFORMATTED" ]; then
    echo -e "${GREEN}✓${NC} All files are properly formatted"
else
    echo -e "${RED}✗${NC} The following files need formatting:"
    echo "$UNFORMATTED"
    echo ""
    echo "Run: gofmt -w ."
    FAILED=1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $FAILED -eq 1 ]; then
    echo -e "${RED}✗ Pre-commit validation FAILED${NC}"
    echo ""
    echo "Fix the issues above before committing."
    echo "To bypass (NOT RECOMMENDED): git commit --no-verify"
    exit 1
fi

echo -e "${GREEN}✓ All pre-commit checks passed${NC}"
echo ""
exit 0
HOOK_EOF

# Make hook executable
chmod +x .git/hooks/pre-commit

echo -e "${GREEN}✓${NC} Pre-commit hook installed successfully"
echo ""
echo "The pre-commit hook will now run automatically before each commit."
echo "It enforces:"
echo "  • go build -o /tmp/eos-build ./cmd/"
echo "  • go vet ./pkg/..."
echo "  • go vet ./cmd/..."
echo "  • gofmt -l (formatting check)"
echo ""
echo "To bypass (NOT RECOMMENDED): git commit --no-verify"
