#!/usr/bin/env bash
# Aggregate test runner for submodule bootstrap pyramid.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=../../scripts/lib/git-env.sh
source "${REPO_ROOT}/scripts/lib/git-env.sh"

# Hooks may export Git-local env vars that break foreign-repo git operations.
ge_unset_git_local_env

echo "[submodule-bootstrap] unit (70%)"
bash "${SCRIPT_DIR}/test-submodule-bootstrap-unit.sh"
echo "[submodule-bootstrap] integration (20%)"
bash "${SCRIPT_DIR}/test-submodule-bootstrap-integration.sh"
echo "[submodule-bootstrap] e2e (10%)"
bash "${SCRIPT_DIR}/test-submodule-bootstrap-e2e.sh"

echo ""
echo "[submodule-bootstrap] test pyramid complete"
