#!/usr/bin/env bash
# Integration tests for scripts/submodule-bootstrap.sh
# Tests: actual submodule state, URL sync, status reporting
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

BOOTSTRAP_SCRIPT="${REPO_ROOT}/scripts/submodule-bootstrap.sh"

# --- Status mode reports all expected fields ---
th_assert_run "integration-status-reports-url" 0 "URL:" bash "${BOOTSTRAP_SCRIPT}" --status
th_assert_run "integration-status-reports-initialized" 0 "Initialized:" bash "${BOOTSTRAP_SCRIPT}" --status
th_assert_run "integration-status-reports-gitmodules" 0 ".gitmodules:" bash "${BOOTSTRAP_SCRIPT}" --status

# --- Idempotent run (no --remote, no --status) ---
# Should succeed without error since submodule is already initialized
th_assert_run "integration-idempotent-run" 0 "bootstrap complete" bash "${BOOTSTRAP_SCRIPT}"

# --- Submodule is populated after bootstrap ---
th_assert_run "integration-submodule-has-claude-md" 0 "" test -f "${REPO_ROOT}/prompts/CLAUDE.md"
th_assert_run "integration-submodule-has-governance" 0 "" test -f "${REPO_ROOT}/prompts/GOVERNANCE-SUMMARY.md"
th_assert_run "integration-submodule-has-soapier" 0 "" test -f "${REPO_ROOT}/prompts/SOAPIER.md"

# --- Symlink is functional ---
th_assert_run "integration-symlink-resolves" 0 "" test -f "${REPO_ROOT}/third_party/prompts/CLAUDE.md"

# --- npm script wiring ---
th_assert_run "integration-npm-has-submodule-init" 0 "submodule:init" grep "submodule:init" "${REPO_ROOT}/package.json"
th_assert_run "integration-npm-has-submodule-update" 0 "submodule:update" grep "submodule:update" "${REPO_ROOT}/package.json"
th_assert_run "integration-npm-has-submodule-status" 0 "submodule:status" grep "submodule:status" "${REPO_ROOT}/package.json"
th_assert_run "integration-npm-has-propagate" 0 "propagate:prompts" grep '"propagate:prompts"' "${REPO_ROOT}/package.json"

th_summary "submodule-bootstrap-integration"
