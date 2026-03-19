#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [[ -z "${REPO_ROOT}" ]]; then
  echo "Error: Not in a git repository" >&2
  exit 1
fi

cd "$REPO_ROOT"

chmod +x .github/hooks/pre-commit .github/hooks/remove-emojis.sh
git config core.hooksPath .github/hooks

echo "Configured git hooks via core.hooksPath=.github/hooks"
echo "Managed hooks:"
echo "  - pre-commit: npm-backed chat archive validation for relevant staged files"
echo "  - remove-emojis.sh: manual emoji cleanup helper"
