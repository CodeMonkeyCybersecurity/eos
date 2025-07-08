#!/bin/bash
# Simple auto-commit script for EOS - Cross-platform compatible
# Usage: ./scripts/auto-commit.sh [message]

set -e

# Detect platform
PLATFORM="unknown"
case "$(uname)" in
    Darwin)  PLATFORM="macos" ;;
    Linux)   PLATFORM="linux" ;;
    CYGWIN*|MINGW*|MSYS*) PLATFORM="windows" ;;
esac

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
FORCE=${FORCE:-false}
PUSH=${PUSH:-false}
DRY_RUN=${DRY_RUN:-false}

echo -e "${CYAN}🚀 EOS Auto-Commit Script${NC}"
echo "=========================="

# Check if we're in the EOS project root
if [ ! -f "go.mod" ] || ! grep -q "github.com/CodeMonkeyCybersecurity/eos" go.mod; then
    echo -e "${RED}❌ Error: Must be run from EOS project root${NC}"
    exit 1
fi

# Check git status
if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    echo -e "${GREEN}No changes to commit${NC}"
    exit 0
fi

# Get current branch
BRANCH=$(git branch --show-current)
echo -e "${BLUE}📂 Branch: ${BRANCH}${NC}"

# Warn about protected branches
if [[ "$BRANCH" == "main" || "$BRANCH" == "master" || "$BRANCH" == "production" ]]; then
    echo -e "${YELLOW}Warning: Committing to protected branch '${BRANCH}'${NC}"
    if [ "$FORCE" != "true" ]; then
        read -p "Continue? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Commit cancelled${NC}"
            exit 0
        fi
    fi
fi

# Show status
echo -e "${CYAN}Files to be committed:${NC}"
git status --porcelain

# Use custom message or generate one
if [ -n "$1" ]; then
    COMMIT_MSG="$1"
else
    # Simple message generation based on file changes
    TOTAL_FILES=$(git status --porcelain | wc -l | tr -d ' ')
    
    # Check for common patterns
    if git status --porcelain | grep -q "test"; then
        COMMIT_MSG="Update tests and related files"
    elif git status --porcelain | grep -q "\.md$"; then
        COMMIT_MSG="Update documentation"
    elif git status --porcelain | grep -q "\.yaml$\|\.yml$\|\.json$"; then
        COMMIT_MSG="Update configuration files"
    elif git status --porcelain | grep -q "^??"; then
        COMMIT_MSG="Add new files and update existing code"
    else
        COMMIT_MSG="Update project files"
    fi
    
    # Add file count
    COMMIT_MSG="${COMMIT_MSG} (${TOTAL_FILES} files)"
fi

# Add standard footer
COMMIT_MSG="${COMMIT_MSG}

 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"

echo -e "${CYAN}📝 Commit message:${NC}"
echo "$COMMIT_MSG"
echo

# Confirmation
if [ "$FORCE" != "true" ] && [ "$DRY_RUN" != "true" ]; then
    read -p "Proceed with commit? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Commit cancelled${NC}"
        exit 0
    fi
fi

if [ "$DRY_RUN" == "true" ]; then
    echo -e "${BLUE}🔍 Dry run - no changes made${NC}"
    exit 0
fi

# Commit
echo -e "${CYAN}💾 Committing changes...${NC}"
git add -A
git commit -m "$COMMIT_MSG"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Commit successful!${NC}"
    
    # Push if requested
    if [ "$PUSH" == "true" ]; then
        echo -e "${CYAN}📤 Pushing to remote...${NC}"
        git push
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Push successful!${NC}"
        else
            echo -e "${RED}❌ Push failed${NC}"
            exit 1
        fi
    fi
else
    echo -e "${RED}❌ Commit failed${NC}"
    exit 1
fi

echo -e "${GREEN}🎉 Auto-commit complete!${NC}"