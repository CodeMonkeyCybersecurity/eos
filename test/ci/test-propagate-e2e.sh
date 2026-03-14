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
