#!/usr/bin/env bash
set -euo pipefail

# Install Git hooks used by local CI parity checks.

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${repo_root}" ]]; then
  echo "Error: not in a git repository"
  exit 1
fi

cd "${repo_root}"
mkdir -p .git/hooks

install_hook() {
  local src="${1:?source required}"
  local dst="${2:?destination required}"
  install -m 0755 "${src}" "${dst}"
}

install_hook "scripts/hooks/pre-commit-ci-debug.sh" ".git/hooks/pre-commit"

echo "Installed pre-commit hook: .git/hooks/pre-commit"
echo "Hook command: mage ci:debug"
