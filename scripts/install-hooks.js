#!/usr/bin/env node
// scripts/install-hooks.js
//
// Installs git hooks for the Eos repository.
// Idempotent: safe to run multiple times.
// Human-centric: explains what it's doing and why.

"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const REPO_ROOT = path.resolve(__dirname, "..");
const HOOKS_DIR = path.join(REPO_ROOT, ".git", "hooks");

// Pre-commit hook content
const PRE_COMMIT_HOOK = `#!/bin/bash
# Eos pre-commit hook
# Installed by: npm run hooks:install
# Purpose: Shift-left validation - catch errors before they reach CI
#
# Runs:
#   1. Repo ownership check (prevents git pull failures)
#   2. Format check (gofmt)
#   3. Go vet (static analysis)
#   4. Go build (compilation check - P0 Rule #10)
#   5. golangci-lint on staged files (if available)
#   6. gitleaks on staged files (if available)
#
# Bypass (NOT recommended): git commit --no-verify
# Reference: CLAUDE.md "Shift-Left Strategy"

set -e

RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[0;33m'
NC='\\033[0m'

echo_status() { echo -e "\${GREEN}[pre-commit]\${NC} $1"; }
echo_warn()   { echo -e "\${YELLOW}[pre-commit]\${NC} $1"; }
echo_fail()   { echo -e "\${RED}[pre-commit]\${NC} $1"; }

# Get staged .go files
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM -- '*.go' | grep -v vendor/ || true)

if [ -z "$STAGED_GO_FILES" ]; then
    echo_status "No staged Go files, skipping Go checks"
    exit 0
fi

# 1. Repository ownership check
echo_status "Checking repository file ownership..."
if command -v node >/dev/null 2>&1 && [ -f "scripts/repo-ownership-check.js" ]; then
    if ! node scripts/repo-ownership-check.js; then
        echo_fail "Repository ownership issues detected. Fix before committing."
        exit 1
    fi
fi

# 2. Format check (staged files only for speed)
echo_status "Checking formatting..."
UNFORMATTED=""
for file in $STAGED_GO_FILES; do
    if [ -f "$file" ]; then
        result=$(gofmt -l "$file" 2>/dev/null || true)
        if [ -n "$result" ]; then
            UNFORMATTED="$UNFORMATTED $file"
        fi
    fi
done

if [ -n "$UNFORMATTED" ]; then
    echo_fail "Files not formatted:"
    for f in $UNFORMATTED; do echo "  $f"; done
    echo_fail "Fix with: gofmt -w <file> or npm run fmt"
    exit 1
fi

# 3. Go vet (staged files only)
echo_status "Running go vet on staged files..."
STAGED_PACKAGES=$(echo "$STAGED_GO_FILES" | xargs -I{} dirname {} | sort -u | sed 's|^|./|')
for pkg in $STAGED_PACKAGES; do
    # Skip packages that require build tags (e2e, integration tests)
    if echo "$pkg" | grep -qE '(test/e2e|test/integration)'; then
        continue
    fi
    if ! go vet "$pkg" 2>/dev/null; then
        echo_fail "go vet failed on $pkg"
        exit 1
    fi
done

# 4. Build check (P0 Rule #10 - CRITICAL)
echo_status "Building project..."
if ! CGO_ENABLED=1 go build -o /tmp/eos-precommit-build ./cmd/ 2>&1; then
    echo_fail "Build FAILED - fix compilation errors before committing"
    exit 1
fi
rm -f /tmp/eos-precommit-build

# 5. golangci-lint (staged files only, if available)
if command -v golangci-lint >/dev/null 2>&1; then
    echo_status "Running golangci-lint on staged files..."
    if ! golangci-lint run --config .golangci.yml --new-from-rev HEAD~0 --timeout 2m 2>/dev/null; then
        echo_warn "golangci-lint reported issues (non-blocking)"
    fi
else
    echo_warn "golangci-lint not installed, skipping (install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)"
fi

# 6. gitleaks (if available)
if command -v gitleaks >/dev/null 2>&1; then
    echo_status "Scanning for secrets..."
    if ! gitleaks protect --staged --no-banner --redact 2>/dev/null; then
        echo_fail "Secrets detected in staged files!"
        exit 1
    fi
fi

echo_status "All pre-commit checks passed"
`;

// Commit-msg hook content
const COMMIT_MSG_HOOK = `#!/bin/bash
# Eos commit message hook
# Enforces conventional commits: <type>(<scope>): <subject>
# Reference: https://www.conventionalcommits.org/en/v1.0.0/

COMMIT_MSG_FILE="$1"
COMMIT_MSG=$(cat "$COMMIT_MSG_FILE")

# Skip merge commits, reverts, fixups
if echo "$COMMIT_MSG" | head -1 | grep -qE '^(Merge|Revert|fixup!|squash!)'; then
    exit 0
fi

PATTERN='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\\([a-zA-Z0-9_-]+\\))?!?: .+'

if ! echo "$COMMIT_MSG" | head -1 | grep -qE "$PATTERN"; then
    echo ""
    echo "Invalid commit message format."
    echo ""
    echo "Expected: <type>(<scope>): <subject>"
    echo "Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
    echo "Example: feat(vault): add cluster authentication hierarchy"
    echo ""
    echo "Your message: $(head -1 "$COMMIT_MSG_FILE")"
    echo ""
    exit 1
fi

# Warn on long subject line
SUBJECT_LENGTH=$(echo "$COMMIT_MSG" | head -1 | wc -c)
if [ "$SUBJECT_LENGTH" -gt 100 ]; then
    echo "[commit-msg] Warning: subject line is $SUBJECT_LENGTH chars (recommended: <100)"
fi
`;

function installHook(name, content) {
  const hookPath = path.join(HOOKS_DIR, name);

  // Check if hook already exists and is identical
  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, "utf8");
    if (existing === content) {
      console.log(`  ${name}: already installed (up to date)`);
      return;
    }
    // Back up existing hook
    const backupPath = `${hookPath}.backup.${Date.now()}`;
    fs.copyFileSync(hookPath, backupPath);
    console.log(`  ${name}: backed up existing hook to ${path.basename(backupPath)}`);
  }

  fs.writeFileSync(hookPath, content, { mode: 0o755 });
  console.log(`  ${name}: installed`);
}

function main() {
  // Verify we're in a git repo
  if (!fs.existsSync(HOOKS_DIR)) {
    try {
      // Maybe .git is a file (worktree)
      const gitPath = path.join(REPO_ROOT, ".git");
      if (fs.existsSync(gitPath) && fs.statSync(gitPath).isFile()) {
        const gitContent = fs.readFileSync(gitPath, "utf8");
        const match = gitContent.match(/gitdir: (.+)/);
        if (match) {
          const hooksDir = path.join(path.resolve(REPO_ROOT, match[1].trim()), "hooks");
          if (!fs.existsSync(hooksDir)) {
            fs.mkdirSync(hooksDir, { recursive: true });
          }
        }
      }
    } catch {
      // Not a git repo
    }

    if (!fs.existsSync(HOOKS_DIR)) {
      console.log("Not a git repository (no .git/hooks directory). Skipping hook installation.");
      return;
    }
  }

  console.log("Installing git hooks...");
  installHook("pre-commit", PRE_COMMIT_HOOK);
  installHook("commit-msg", COMMIT_MSG_HOOK);
  console.log("Done. Hooks will run automatically on git commit.");
  console.log("Bypass with: git commit --no-verify (not recommended)");
}

main();
