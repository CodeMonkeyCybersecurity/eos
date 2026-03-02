#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${repo_root}"
# shellcheck source=../lib/git-env.sh
source "${repo_root}/scripts/lib/git-env.sh"

staged_files="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "${staged_files}" ]]; then
  echo "pre-commit: no staged changes"
  exit 0
fi

# Clear hook-exported Git env vars before running ci:debug. This prevents
# cross-repo Git operations in tests from inheriting hook-scoped values.
ge_unset_git_local_env

echo "pre-commit: verifying ci:debug parity contract"
bash "${repo_root}/scripts/ci/verify-parity.sh"

echo "pre-commit: running ci:debug"
if [[ -f "${repo_root}/package.json" ]] && command -v npm >/dev/null 2>&1; then
  npm run ci:debug --silent
else
  bash "${repo_root}/scripts/ci/debug.sh"
fi

if echo "${staged_files}" | grep -Eq '^(pkg/self/|pkg/git/|pkg/vault/phase2_env_setup\.go|cmd/self/|scripts/ci/self-update-quality\.sh|test/e2e/smoke/self/|package\.json)'; then
  echo "pre-commit: running self-update quality lane"
  if [[ -f "${repo_root}/package.json" ]] && command -v npm >/dev/null 2>&1; then
    npm run ci:self-update-quality --silent
  else
    bash "${repo_root}/scripts/ci/self-update-quality.sh"
  fi
fi
