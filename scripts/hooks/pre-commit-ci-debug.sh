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

echo "pre-commit: running mage ci:debug"
if [[ -x "${repo_root}/magew" ]]; then
  "${repo_root}/magew" ci:debug
else
  mage ci:debug
fi
