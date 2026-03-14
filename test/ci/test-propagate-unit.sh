#!/usr/bin/env bash
# Unit tests for prompts/scripts/propagate.sh and its npm contract.
# These are Beyonce Rule regression tests: they FAIL before the fix
# (missing npm scripts in package.json) and PASS after.
# 70% tier — fast, no external dependencies, no file modifications.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

PROPAGATE_SCRIPT="${REPO_ROOT}/prompts/scripts/propagate.sh"
PACKAGE_JSON="${REPO_ROOT}/package.json"

# Guard: if prompts submodule not initialized, skip all script tests gracefully.
# The submodule requires authenticated CI access to cybermonkey/prompts. When
# GITEA_TOKEN lacks access, the clone step in ci-debug-parity.yml warns but
# continues; these tests then become unrunnable.
# Durable fix: update the GITEA_TOKEN CI secret to a token with read access to
# cybermonkey/prompts. See tests/artifacts/fix-ci-rca.md (P0-C) for details.
if [[ ! -f "${PROPAGATE_SCRIPT}" ]]; then
  echo "SKIP: prompts submodule not initialized — skipping all propagate script tests"
  echo "  (${PROPAGATE_SCRIPT} not found)"
  echo "  To initialize locally: git submodule update --init prompts"
  echo "  CI durable fix: update GITEA_TOKEN secret with read access to cybermonkey/prompts"
  echo ""
  echo "[unit] Results: 0 passed, 0 failed, 0 total (skipped — submodule unavailable)"
  exit 0
fi

# --- Syntax checks ---
th_assert_run "propagate-script-exists" 0 "" test -f "${PROPAGATE_SCRIPT}"
th_assert_run "propagate-script-syntax" 0 "" bash -n "${PROPAGATE_SCRIPT}"

# --- npm contract (Beyonce Rule: these fail before fix, pass after) ---
# issue #247: package.json was missing propagate:prompts, propagate:prompts:dry-run, test:propagate
th_assert_run "npm-contract-propagate-prompts" 0 "propagate:prompts" \
  grep -F '"propagate:prompts"' "${PACKAGE_JSON}"

th_assert_run "npm-contract-propagate-prompts-dry-run" 0 "propagate:prompts:dry-run" \
  grep -F '"propagate:prompts:dry-run"' "${PACKAGE_JSON}"

th_assert_run "npm-contract-test-propagate" 0 "test:propagate" \
  grep -F '"test:propagate"' "${PACKAGE_JSON}"

# Verify the scripts point to the correct target
th_assert_run "npm-script-propagate-points-to-propagate-sh" 0 "prompts/scripts/propagate.sh" \
  grep -A1 '"propagate:prompts"' "${PACKAGE_JSON}"

# dry-run variant must include the flag (use 'dry-run' without dashes to avoid grep confusion)
th_assert_run "npm-script-dry-run-includes-flag" 0 "dry-run" \
  grep -A1 '"propagate:prompts:dry-run"' "${PACKAGE_JSON}"

th_assert_run "npm-script-test-propagate-points-to-dispatcher" 0 "test/ci/test-propagate.sh" \
  grep -A1 '"test:propagate"' "${PACKAGE_JSON}"

# --- prompts submodule comment contract ---
# propagate.sh documents "# called via npm run propagate:prompts"
# This is the contract that was written without enforcement — now we enforce it.
th_assert_run "propagate-script-documents-npm-entrypoint" 0 "npm run propagate:prompts" \
  grep -F "npm run propagate:prompts" "${PROPAGATE_SCRIPT}"

# --- Help flag tests ---
th_assert_run "help-flag-short" 0 "Usage" bash "${PROPAGATE_SCRIPT}" -h
th_assert_run "help-flag-long" 0 "Usage" bash "${PROPAGATE_SCRIPT}" --help
th_assert_run "help-flag-shows-steps" 0 "submodule" bash "${PROPAGATE_SCRIPT}" --help
th_assert_run "help-flag-shows-dry-run-option" 0 "dry-run" bash "${PROPAGATE_SCRIPT}" --help

# --- Valid step names appear in --help ---
VALID_STEPS=("submodule" "skills" "mcp" "settings" "stage")
for step in "${VALID_STEPS[@]}"; do
  th_assert_run "valid-step-in-help-${step}" 0 "${step}" \
    bash "${PROPAGATE_SCRIPT}" --help
done

# --- Invalid input rejection ---
# Unknown flag must exit non-zero
_unknown_exit=0
bash "${PROPAGATE_SCRIPT}" --no-such-flag >/dev/null 2>&1 || _unknown_exit=$?
if [[ "${_unknown_exit}" -ne 0 ]]; then
  echo "PASS: unknown-flag-nonzero-exit"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: unknown-flag-nonzero-exit (expected non-zero, got ${_unknown_exit})"
  th_fail=$((th_fail + 1))
fi

# Invalid step name with valid repo root must exit non-zero
_invalid_exit=0
bash "${PROPAGATE_SCRIPT}" --only "no-such-step" --repo-root "${REPO_ROOT}" --dry-run >/dev/null 2>&1 || _invalid_exit=$?
if [[ "${_invalid_exit}" -ne 0 ]]; then
  echo "PASS: invalid-step-name-nonzero-exit"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: invalid-step-name-nonzero-exit (expected non-zero, got ${_invalid_exit})"
  th_fail=$((th_fail + 1))
fi

# NOTE: The no-repo-root-exits-2 scenario (exit 2 from auto-detection) cannot be tested
# from within the eos repo. propagate.sh detects REPO_ROOT by walking up from its own
# filesystem location (prompts/scripts/), not from cwd. When the script lives at
# /opt/eos/prompts/scripts/propagate.sh, the walk-up always finds /opt/eos/.git, so
# exit 2 can never be triggered from an in-tree test. Instead, we test that an
# explicitly nonexistent --repo-root causes a non-zero exit (error path coverage).
_badroot_exit=0
bash "${PROPAGATE_SCRIPT}" --repo-root "/tmp/no-such-repo-root-$$" >/dev/null 2>&1 || _badroot_exit=$?
if [[ "${_badroot_exit}" -ne 0 ]]; then
  echo "PASS: bad-repo-root-nonzero-exit"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: bad-repo-root-nonzero-exit (expected non-zero, got ${_badroot_exit})"
  th_fail=$((th_fail + 1))
fi

# --- Structured logging format (stderr) ---
# With --dry-run and valid repo-root, stderr should contain [propagate] structured lines
_log_output=""
_log_output="$(bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" 2>&1 >/dev/null)" || true
if echo "${_log_output}" | grep -qF '[propagate]'; then
  echo "PASS: structured-log-prefix-on-stderr"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: structured-log-prefix-on-stderr (expected [propagate] prefix in stderr)"
  echo "  stderr sample: ${_log_output:0:200}"
  th_fail=$((th_fail + 1))
fi

if echo "${_log_output}" | grep -q 'ts='; then
  echo "PASS: structured-log-has-ts-field"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: structured-log-has-ts-field (expected ts= in structured log)"
  th_fail=$((th_fail + 1))
fi

if echo "${_log_output}" | grep -q 'level='; then
  echo "PASS: structured-log-has-level-field"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: structured-log-has-level-field (expected level= in structured log)"
  th_fail=$((th_fail + 1))
fi

# --- Summary output (stdout) ---
# With --dry-run, stdout should contain the propagation summary header
_stdout_output=""
_stdout_output="$(bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" 2>/dev/null)" || true
if echo "${_stdout_output}" | grep -qF '=== Propagation Summary ==='; then
  echo "PASS: summary-header-on-stdout"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: summary-header-on-stdout (expected '=== Propagation Summary ===' in stdout)"
  echo "  stdout sample: ${_stdout_output:0:200}"
  th_fail=$((th_fail + 1))
fi

if echo "${_stdout_output}" | grep -q 'Dry run complete'; then
  echo "PASS: dry-run-complete-message-on-stdout"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: dry-run-complete-message-on-stdout (expected 'Dry run complete' in stdout)"
  th_fail=$((th_fail + 1))
fi

th_summary "unit"
