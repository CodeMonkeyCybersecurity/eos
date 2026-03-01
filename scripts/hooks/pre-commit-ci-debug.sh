#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${repo_root}"

staged_files="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "${staged_files}" ]]; then
  echo "pre-commit: no staged changes"
  exit 0
fi

# Unset GIT_INDEX_FILE so subprocesses (e.g. submodule-freshness integration
# tests that create temp repos) don't inherit the pre-commit lock file path.
unset GIT_INDEX_FILE

echo "pre-commit: running mage ci:debug"
if [[ -x "${repo_root}/magew" ]]; then
  "${repo_root}/magew" ci:debug
else
  mage ci:debug
fi
