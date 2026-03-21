#!/bin/bash
# Setup script to install Git hooks for Eos project
# Run this after cloning the repository: ./.github/hooks/setup-hooks.sh

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}Setting up Git hooks for Eos...${NC}\n"

# Get the repository root
REPO_ROOT=$(git rev-parse --show-toplevel)
HOOKS_DIR="$REPO_ROOT/.git/hooks"
SOURCE_DIR="$REPO_ROOT/.github/hooks"

# Ensure hooks directory exists
mkdir -p "$HOOKS_DIR"

# Install pre-commit hook
echo -e "${BLUE}Installing pre-commit hook...${NC}"
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    echo -e "${YELLOW}Warning: pre-commit hook already exists${NC}"
    read -p "Overwrite? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Skipping pre-commit hook installation${NC}"
    else
        cp "$SOURCE_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
        chmod +x "$HOOKS_DIR/pre-commit"
        echo -e "${GREEN}✓ Pre-commit hook installed${NC}"
    fi
else
    cp "$SOURCE_DIR/pre-commit" "$HOOKS_DIR/pre-commit"
    chmod +x "$HOOKS_DIR/pre-commit"
    echo -e "${GREEN}✓ Pre-commit hook installed${NC}"
fi

# Make remove-emojis.sh executable
chmod +x "$SOURCE_DIR/remove-emojis.sh"
echo -e "${GREEN}✓ Remove-emojis script is executable${NC}"

echo -e "\n${GREEN}Git hooks setup complete!${NC}"
echo -e "\n${BLUE}Installed hooks:${NC}"
echo -e "  - pre-commit: Automatically removes emojis from staged Go files"

echo -e "\n${YELLOW}Note: To manually run emoji removal on all files:${NC}"
echo -e "  ./.github/hooks/remove-emojis.sh [--dry-run]"

echo -e "\n${BLUE}To disable hooks temporarily, use:${NC}"
echo -e "  git commit --no-verify"
