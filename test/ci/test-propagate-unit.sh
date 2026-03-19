#!/usr/bin/env bash
# Unit tests for prompts/scripts/propagate.sh and its npm contract.
# These are Beyonce Rule regression tests: they FAIL before the fix
# (missing npm scripts in package.json) and PASS after.
# 70% tier — fast, no external dependencies, no file modifications.
#
# GUARD: The dispatcher (test-propagate.sh) checks for submodule presence
# before calling this file. If you run this file directly, ensure
# prompts/scripts/propagate.sh exists.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

PROPAGATE_SCRIPT="${REPO_ROOT}/prompts/scripts/propagate.sh"
PACKAGE_JSON="${REPO_ROOT}/package.json"
DISPATCHER_SCRIPT="${REPO_ROOT}/test/ci/test-propagate.sh"

# --- Syntax checks ---
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
th_assert_nonzero_exit "unknown-flag-nonzero-exit" "${_unknown_exit}"

# Invalid step name with valid repo root must exit non-zero
_invalid_exit=0
bash "${PROPAGATE_SCRIPT}" --only "no-such-step" --repo-root "${REPO_ROOT}" --dry-run >/dev/null 2>&1 || _invalid_exit=$?
th_assert_nonzero_exit "invalid-step-name-nonzero-exit" "${_invalid_exit}"

# NOTE: The no-repo-root-exits-2 scenario (exit 2 from auto-detection) cannot be tested
# from within the eos repo. propagate.sh detects REPO_ROOT by walking up from its own
# filesystem location (prompts/scripts/), not from cwd. When the script lives at
# /opt/eos/prompts/scripts/propagate.sh, the walk-up always finds /opt/eos/.git, so
# exit 2 can never be triggered from an in-tree test. Instead, we test that an
# explicitly nonexistent --repo-root causes a non-zero exit (error path coverage).
_badroot_exit=0
bash "${PROPAGATE_SCRIPT}" --repo-root "/tmp/no-such-repo-root-$$" >/dev/null 2>&1 || _badroot_exit=$?
th_assert_nonzero_exit "bad-repo-root-nonzero-exit" "${_badroot_exit}"

# --- Structured logging format (stderr) ---
# With --dry-run and valid repo-root, stderr should contain [propagate] structured lines
_log_output=""
_log_output="$(bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" 2>&1 >/dev/null)" || true
th_assert_contains "structured-log-prefix-on-stderr" "${_log_output}" "[propagate]"
th_assert_contains "structured-log-has-ts-field" "${_log_output}" "ts="
th_assert_contains "structured-log-has-level-field" "${_log_output}" "level="

# --- Summary output (stdout) ---
# With --dry-run, stdout should contain the propagation summary header
_stdout_output=""
_stdout_output="$(bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" 2>/dev/null)" || true
th_assert_contains "summary-header-on-stdout" "${_stdout_output}" "=== Propagation Summary ==="
th_assert_contains "dry-run-complete-message-on-stdout" "${_stdout_output}" "Dry run complete"

# --- Dispatcher regression: missing prompts submodule skips with durable artifacts ---
_dispatcher_skip_tmp="$(mktemp -d)"
trap 'rm -rf "${_dispatcher_skip_tmp}" "${_dispatcher_fail_tmp:-}"' EXIT
mkdir -p "${_dispatcher_skip_tmp}/repo"
_dispatcher_skip_report="${_dispatcher_skip_tmp}/artifacts/skip-report.json"
_dispatcher_skip_metrics="${_dispatcher_skip_tmp}/artifacts/skip-metrics.prom"
_dispatcher_skip_events="${_dispatcher_skip_tmp}/artifacts/skip-events.jsonl"

_dispatcher_skip_output=""
_dispatcher_skip_exit=0
_dispatcher_skip_output="$(
  env \
    PROPAGATE_TEST_REPO_ROOT="${_dispatcher_skip_tmp}/repo" \
    PROPAGATE_REPORT_JSON="${_dispatcher_skip_report}" \
    PROPAGATE_METRICS_TEXTFILE="${_dispatcher_skip_metrics}" \
    PROPAGATE_EVENTS_JSONL="${_dispatcher_skip_events}" \
    bash "${DISPATCHER_SCRIPT}" 2>&1
)" || _dispatcher_skip_exit=$?

th_assert_exit_code "dispatcher-skip-exits-0" "${_dispatcher_skip_exit}" 0
th_assert_contains "dispatcher-skip-announces-submodule-missing" "${_dispatcher_skip_output}" "SKIP: prompts submodule not initialized"
th_assert_contains "dispatcher-skip-completes-cleanly" "${_dispatcher_skip_output}" "all tiers skipped"
th_assert_file_exists "dispatcher-skip-report-written" "${_dispatcher_skip_report}"
th_assert_file_exists "dispatcher-skip-metrics-written" "${_dispatcher_skip_metrics}"
th_assert_file_exists "dispatcher-skip-events-written" "${_dispatcher_skip_events}"
th_assert_json_field "dispatcher-skip-report-kind" "${_dispatcher_skip_report}" "kind" "propagate"
th_assert_json_field "dispatcher-skip-report-status" "${_dispatcher_skip_report}" "status" "skip"
th_assert_json_field "dispatcher-skip-report-outcome" "${_dispatcher_skip_report}" "outcome" "skip_submodule_unavailable"
th_assert_json_field "dispatcher-skip-unit-status" "${_dispatcher_skip_report}" "unit_status" "skip"
th_assert_json_field "dispatcher-skip-integration-status" "${_dispatcher_skip_report}" "integration_status" "skip"
th_assert_json_field "dispatcher-skip-e2e-status" "${_dispatcher_skip_report}" "e2e_status" "skip"
th_assert_run "dispatcher-skip-metrics-status" 0 'propagate_pyramid_status{status="skip"} 1' \
  grep -F 'propagate_pyramid_status{status="skip"} 1' "${_dispatcher_skip_metrics}"
th_assert_run "dispatcher-skip-events-have-reason" 0 '"reason":"prompts_submodule_unavailable"' \
  grep -F '"reason":"prompts_submodule_unavailable"' "${_dispatcher_skip_events}"

# --- Dispatcher regression: failing tier must not short-circuit later tiers ---
_dispatcher_fail_tmp="$(mktemp -d)"
mkdir -p "${_dispatcher_fail_tmp}/repo/prompts/scripts" "${_dispatcher_fail_tmp}/tiers" "${_dispatcher_fail_tmp}/artifacts"
cat > "${_dispatcher_fail_tmp}/repo/prompts/scripts/propagate.sh" <<'EOF_PROPAGATE'
#!/usr/bin/env bash
exit 0
EOF_PROPAGATE
chmod +x "${_dispatcher_fail_tmp}/repo/prompts/scripts/propagate.sh"

cat > "${_dispatcher_fail_tmp}/tiers/test-propagate-unit.sh" <<'EOF_UNIT'
#!/usr/bin/env bash
echo "[unit] Results: 0 passed, 1 failed, 1 total"
exit 1
EOF_UNIT
cat > "${_dispatcher_fail_tmp}/tiers/test-propagate-integration.sh" <<'EOF_INTEGRATION'
#!/usr/bin/env bash
echo "[integration] Results: 1 passed, 0 failed, 1 total"
exit 0
EOF_INTEGRATION
cat > "${_dispatcher_fail_tmp}/tiers/test-propagate-e2e.sh" <<'EOF_E2E'
#!/usr/bin/env bash
echo "[e2e] Results: 1 passed, 0 failed, 1 total"
exit 0
EOF_E2E
chmod +x \
  "${_dispatcher_fail_tmp}/tiers/test-propagate-unit.sh" \
  "${_dispatcher_fail_tmp}/tiers/test-propagate-integration.sh" \
  "${_dispatcher_fail_tmp}/tiers/test-propagate-e2e.sh"

_dispatcher_fail_report="${_dispatcher_fail_tmp}/artifacts/fail-report.json"
_dispatcher_fail_metrics="${_dispatcher_fail_tmp}/artifacts/fail-metrics.prom"
_dispatcher_fail_events="${_dispatcher_fail_tmp}/artifacts/fail-events.jsonl"
_dispatcher_fail_output=""
_dispatcher_fail_exit=0
_dispatcher_fail_output="$(
  env \
    PROPAGATE_TEST_REPO_ROOT="${_dispatcher_fail_tmp}/repo" \
    PROPAGATE_TEST_TIERS_DIR="${_dispatcher_fail_tmp}/tiers" \
    PROPAGATE_REPORT_JSON="${_dispatcher_fail_report}" \
    PROPAGATE_METRICS_TEXTFILE="${_dispatcher_fail_metrics}" \
    PROPAGATE_EVENTS_JSONL="${_dispatcher_fail_events}" \
    bash "${DISPATCHER_SCRIPT}" 2>&1
)" || _dispatcher_fail_exit=$?

th_assert_nonzero_exit "dispatcher-tier-failure-exits-nonzero" "${_dispatcher_fail_exit}"
th_assert_contains "dispatcher-tier-failure-runs-unit" "${_dispatcher_fail_output}" "[propagate] unit (70%)"
th_assert_contains "dispatcher-tier-failure-runs-integration" "${_dispatcher_fail_output}" "[propagate] integration (20%)"
th_assert_contains "dispatcher-tier-failure-runs-e2e" "${_dispatcher_fail_output}" "[propagate] e2e (10%)"
th_assert_contains "dispatcher-tier-failure-summarises-final-state" "${_dispatcher_fail_output}" "test pyramid complete (1 tier(s) failed)"
th_assert_file_exists "dispatcher-tier-failure-report-written" "${_dispatcher_fail_report}"
th_assert_json_field "dispatcher-tier-failure-status" "${_dispatcher_fail_report}" "status" "fail"
th_assert_json_field "dispatcher-tier-failure-outcome" "${_dispatcher_fail_report}" "outcome" "fail_tier_failures"
th_assert_json_field "dispatcher-tier-failure-unit-status" "${_dispatcher_fail_report}" "unit_status" "fail"
th_assert_json_field "dispatcher-tier-failure-integration-status" "${_dispatcher_fail_report}" "integration_status" "pass"
th_assert_json_field "dispatcher-tier-failure-e2e-status" "${_dispatcher_fail_report}" "e2e_status" "pass"
th_assert_run "dispatcher-tier-failure-metrics-count" 0 "propagate_pyramid_tiers_failed_total 1" \
  grep -F "propagate_pyramid_tiers_failed_total 1" "${_dispatcher_fail_metrics}"
th_assert_run "dispatcher-tier-failure-events-finish" 0 '"event":"propagate.finish"' \
  grep -F '"event":"propagate.finish"' "${_dispatcher_fail_events}"

th_summary "unit"
