#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=../../scripts/lib/git-env.sh
source "${REPO_ROOT}/scripts/lib/git-env.sh"
ge_unset_git_local_env

echo "[propagate] unit (70%)"
bash "${SCRIPT_DIR}/test-propagate-unit.sh"

echo "[propagate] integration (20%)"
bash "${SCRIPT_DIR}/test-propagate-integration.sh"

echo "[propagate] e2e (10%)"
bash "${SCRIPT_DIR}/test-propagate-e2e.sh"

echo ""
echo "[propagate] test pyramid complete"
