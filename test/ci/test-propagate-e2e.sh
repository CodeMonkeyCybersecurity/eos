#!/usr/bin/env bash
# E2E tests for the propagate:prompts npm script.
# Runs the full npm entrypoint from the eos repo root.
# 10% tier — full user-facing flow, safe because we only invoke --dry-run variant.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

# All e2e tests run from repo root to simulate real developer/CI invocation
cd "${REPO_ROOT}"

# Guard: skip all e2e tests if prompts submodule not initialized.
# npm run propagate:prompts:dry-run internally invokes prompts/scripts/propagate.sh
# which does not exist when the submodule is uncloned (exit 127).
# See test-propagate-unit.sh and tests/artifacts/fix-ci-rca.md (P0-C) for context.
if [[ ! -f "${REPO_ROOT}/prompts/scripts/propagate.sh" ]]; then
  echo "SKIP: prompts submodule not initialized — skipping all propagate e2e tests"
  echo "  (${REPO_ROOT}/prompts/scripts/propagate.sh not found)"
  echo "  CI durable fix: update GITEA_TOKEN secret with read access to cybermonkey/prompts"
  echo ""
  echo "[e2e] Results: 0 passed, 0 failed, 0 total (skipped — submodule unavailable)"
  exit 0
fi

# --- npm run propagate:prompts:dry-run succeeds ---
# This is the primary regression test for issue #247:
# Before the fix, this would fail with "npm error Missing script: propagate:prompts:dry-run"
th_assert_run "npm-propagate-prompts-dry-run-exits-0" 0 "" \
  npm run propagate:prompts:dry-run --silent

# --- dry-run produces expected output ---
th_assert_run "npm-propagate-prompts-dry-run-has-summary" 0 "=== Propagation Summary ===" \
  npm run propagate:prompts:dry-run --silent

th_assert_run "npm-propagate-prompts-dry-run-no-files-modified" 0 "No files were modified" \
  npm run propagate:prompts:dry-run --silent

# --- npm run propagate:prompts is registered (listed by npm run) ---
# Before the fix this was missing; after the fix it must appear.
# Unset npm_config_loglevel so the parent 'npm run ci:debug --silent' invocation
# does not suppress child npm output (npm propagates loglevel via env var).
th_assert_run "npm-script-propagate-prompts-listed" 0 "propagate:prompts" \
  env -u npm_config_loglevel npm run

# --- test:propagate dispatcher itself is reachable ---
# This meta-test verifies the CI wiring: npm run test:propagate must exist
# (actual pass/fail of sub-tests is handled by the dispatcher itself)
th_assert_run "npm-test-propagate-script-registered" 0 "test:propagate" \
  env -u npm_config_loglevel npm run

th_summary "e2e"
