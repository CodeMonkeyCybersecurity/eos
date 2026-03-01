#!/usr/bin/env bash
# Aggregate test runner for submodule freshness pyramid.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=../../scripts/lib/git-env.sh
source "${REPO_ROOT}/scripts/lib/git-env.sh"

# Hooks may export Git-local env vars that break foreign-repo git operations.
ge_unset_git_local_env

echo "[submodule-freshness] unit (70%)"
bash "${SCRIPT_DIR}/test-submodule-freshness-unit.sh"
echo "[submodule-freshness] integration (20%)"
bash "${SCRIPT_DIR}/test-submodule-freshness-integration.sh"
echo "[submodule-freshness] e2e (10%)"
bash "${SCRIPT_DIR}/test-submodule-freshness-e2e.sh"

echo ""
echo "[submodule-freshness] test pyramid complete"
