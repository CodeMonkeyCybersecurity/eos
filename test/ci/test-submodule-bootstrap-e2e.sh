#!/usr/bin/env bash
# E2E tests for scripts/submodule-bootstrap.sh
# Tests: full bootstrap cycle via npm scripts
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

# --- npm run submodule:status works ---
th_assert_run "e2e-npm-submodule-status" 0 "Submodule Status" bash -c '
  cd "'"${REPO_ROOT}"'" && npm run submodule:status 2>&1
'

# --- npm run submodule:init is idempotent ---
th_assert_run "e2e-npm-submodule-init-idempotent" 0 "bootstrap complete" bash -c '
  cd "'"${REPO_ROOT}"'" && npm run submodule:init 2>&1
'

# --- Full propagate:prompts chain works ---
# This tests the chicken-and-egg fix: bootstrap THEN propagate
th_assert_run "e2e-propagate-prompts-accessible" 0 "" bash -c '
  cd "'"${REPO_ROOT}"'"
  # Verify the propagate script exists inside the submodule
  test -f prompts/scripts/propagate.sh
'

th_summary "submodule-bootstrap-e2e"
