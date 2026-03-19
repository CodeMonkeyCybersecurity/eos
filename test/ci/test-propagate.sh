#!/usr/bin/env bash
# Dispatcher for the propagation test pyramid (unit 70% / integration 20% / e2e 10%).
# CANONICAL guard: if prompts submodule is not initialized, all tiers skip here.
# Individual tier scripts do NOT need their own guards — this is the single check point.
#
# This runner is intentionally resilient:
#   - missing prompts submodule => graceful skip with structured artifacts
#   - failing tier => continue remaining tiers, then emit a final report
#   - repeated runs => idempotent outputs in outputs/ci/propagate/
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=../../scripts/lib/git-env.sh
source "${REPO_ROOT}/scripts/lib/git-env.sh"
# shellcheck source=../../scripts/lib/ci-common.sh
source "${REPO_ROOT}/scripts/lib/ci-common.sh"
ge_unset_git_local_env

TEST_REPO_ROOT="${PROPAGATE_TEST_REPO_ROOT:-${REPO_ROOT}}"
TEST_TIERS_DIR="${PROPAGATE_TEST_TIERS_DIR:-${SCRIPT_DIR}}"
PROPAGATE_SCRIPT="${PROPAGATE_TEST_PROPAGATE_SCRIPT:-${TEST_REPO_ROOT}/prompts/scripts/propagate.sh}"
OUTPUT_DIR="${PROPAGATE_OUTPUT_DIR:-${REPO_ROOT}/outputs/ci/propagate}"
REPORT_JSON="${PROPAGATE_REPORT_JSON:-${OUTPUT_DIR}/report.json}"
METRICS_TEXTFILE="${PROPAGATE_METRICS_TEXTFILE:-${OUTPUT_DIR}/metrics.prom}"
EVENTS_JSONL="${PROPAGATE_EVENTS_JSONL:-${OUTPUT_DIR}/events.jsonl}"
RUN_ID="$(ci_now_utc | tr -d ':T-' | cut -c1-15)Z-$$"
START_EPOCH="$(ci_epoch)"
FINALIZED=false

UNIT_STATUS="pending"
INTEGRATION_STATUS="pending"
E2E_STATUS="pending"
TIERS_TOTAL=3
TIERS_SKIPPED=0
TIERS_FAILED=0

mkdir -p \
  "${OUTPUT_DIR}" \
  "$(dirname "${REPORT_JSON}")" \
  "$(dirname "${METRICS_TEXTFILE}")" \
  "$(dirname "${EVENTS_JSONL}")"
: > "${EVENTS_JSONL}"

log_event() {
  local level="${1:?level required}"
  local event="${2:?event required}"
  local message="${3:-}"
  shift 3

  local payload
  payload="$(ci_json_obj \
    ts             "$(ci_now_utc)" \
    run_id         "${RUN_ID}" \
    kind           "propagate" \
    level          "${level}" \
    event          "${event}" \
    message        "${message}" \
    repo_root      "${TEST_REPO_ROOT}" \
    propagate_path "${PROPAGATE_SCRIPT}" \
    "$@")"
  printf '%s\n' "${payload}" >> "${EVENTS_JSONL}"
  printf '[propagate] ts=%s level=%s event=%s %s\n' "$(ci_now_utc)" "${level}" "${event}" "${message}" >&2
}

emit_metrics() {
  local status="${1:?status required}"
  local duration_seconds="${2:?duration required}"

  cat > "${METRICS_TEXTFILE}" <<EOF_METRICS
# TYPE propagate_pyramid_status gauge
propagate_pyramid_status{status="${status}"} 1
# TYPE propagate_pyramid_duration_seconds gauge
propagate_pyramid_duration_seconds ${duration_seconds}
# TYPE propagate_pyramid_tiers_total gauge
propagate_pyramid_tiers_total ${TIERS_TOTAL}
# TYPE propagate_pyramid_tiers_skipped_total gauge
propagate_pyramid_tiers_skipped_total ${TIERS_SKIPPED}
# TYPE propagate_pyramid_tiers_failed_total gauge
propagate_pyramid_tiers_failed_total ${TIERS_FAILED}
# TYPE propagate_pyramid_tier_status gauge
propagate_pyramid_tier_status{tier="unit",status="${UNIT_STATUS}"} 1
propagate_pyramid_tier_status{tier="integration",status="${INTEGRATION_STATUS}"} 1
propagate_pyramid_tier_status{tier="e2e",status="${E2E_STATUS}"} 1
# TYPE propagate_pyramid_last_run_timestamp_seconds gauge
propagate_pyramid_last_run_timestamp_seconds ${START_EPOCH}
EOF_METRICS
}

emit_report() {
  local status="${1:?status required}"
  local outcome="${2:?outcome required}"
  local message="${3:?message required}"
  local exit_code="${4:?exit code required}"
  local duration_seconds
  duration_seconds="$(( $(ci_epoch) - START_EPOCH ))"

  printf '%s\n' "$(ci_json_obj \
    schema_version   "1" \
    kind             "propagate" \
    ts               "$(ci_now_utc)" \
    run_id           "${RUN_ID}" \
    status           "${status}" \
    outcome          "${outcome}" \
    exit_code        "#int:${exit_code}" \
    duration_seconds "#int:${duration_seconds}" \
    tiers_total      "#int:${TIERS_TOTAL}" \
    tiers_skipped    "#int:${TIERS_SKIPPED}" \
    tiers_failed     "#int:${TIERS_FAILED}" \
    unit_status      "${UNIT_STATUS}" \
    integration_status "${INTEGRATION_STATUS}" \
    e2e_status       "${E2E_STATUS}" \
    repo_root        "${TEST_REPO_ROOT}" \
    propagate_path   "${PROPAGATE_SCRIPT}" \
    events_path      "${EVENTS_JSONL}" \
    metrics_path     "${METRICS_TEXTFILE}" \
    message          "${message}")" > "${REPORT_JSON}"
  emit_metrics "${status}" "${duration_seconds}"
}

finish() {
  local status="${1:?status required}"
  local outcome="${2:?outcome required}"
  local message="${3:?message required}"
  local exit_code="${4:?exit code required}"

  trap - ERR
  emit_report "${status}" "${outcome}" "${message}" "${exit_code}"
  FINALIZED=true
  exit "${exit_code}"
}

on_err() {
  local exit_code="$?"
  local line="${1:-0}"
  local command="${2:-unknown}"

  if [[ "${FINALIZED}" == "true" ]]; then
    exit "${exit_code}"
  fi

  log_event "error" "propagate.unexpected_error" \
    "Unexpected error at line=${line} command=${command}" \
    line "#int:${line}" \
    failed_command "${command}" \
    exit_code "#int:${exit_code}"
  finish "fail" "fail_internal_error" \
    "Propagation test pyramid failed unexpectedly at line ${line}" "${exit_code}"
}

trap 'on_err "${LINENO}" "${BASH_COMMAND}"' ERR

set_tier_status() {
  local tier="${1:?tier required}"
  local status="${2:?status required}"
  case "${tier}" in
    unit) UNIT_STATUS="${status}" ;;
    integration) INTEGRATION_STATUS="${status}" ;;
    e2e) E2E_STATUS="${status}" ;;
    *)
      printf 'unknown tier: %s\n' "${tier}" >&2
      return 1
      ;;
  esac
}

run_tier() {
  local tier="${1:?tier required}"
  local weight="${2:?weight required}"
  local script_path="${3:?script path required}"
  local exit_code=0

  echo "[propagate] ${tier} (${weight})"
  log_event "info" "propagate.tier.start" "Starting ${tier} tier" tier "${tier}" script "${script_path}"

  if bash "${script_path}"; then
    set_tier_status "${tier}" "pass"
    log_event "info" "propagate.tier.finish" "${tier} tier passed" tier "${tier}" exit_code "#int:0"
    return 0
  else
    exit_code=$?
  fi

  TIERS_FAILED=$((TIERS_FAILED + 1))
  set_tier_status "${tier}" "fail"
  log_event "error" "propagate.tier.finish" "${tier} tier failed" tier "${tier}" exit_code "#int:${exit_code}"
  return "${exit_code}"
}

# --- Canonical submodule guard ---
# The prompts submodule requires authenticated access to cybermonkey/prompts.
# When the submodule is not initialized (CI auth issue, fresh clone without
# --recurse-submodules), skip ALL propagation tests gracefully.
# Durable fix: update the GITEA_TOKEN CI secret with read access to cybermonkey/prompts.
if [[ ! -f "${PROPAGATE_SCRIPT}" ]]; then
  echo "SKIP: prompts submodule not initialized — skipping entire propagation test pyramid"
  echo "  (${PROPAGATE_SCRIPT} not found)"
  echo "  To initialize locally: git submodule update --init prompts"
  echo "  CI durable fix: update GITEA_TOKEN secret with read access to cybermonkey/prompts"
  echo ""
  UNIT_STATUS="skip"
  INTEGRATION_STATUS="skip"
  E2E_STATUS="skip"
  TIERS_SKIPPED="${TIERS_TOTAL}"
  log_event "warn" "propagate.skip" \
    "prompts submodule unavailable; skipping propagation pyramid" \
    outcome "skip_submodule_unavailable" \
    reason "prompts_submodule_unavailable" \
    tiers_skipped "#int:${TIERS_SKIPPED}"
  echo "[unit] Results: 0 passed, 0 failed, 0 total (skipped)"
  echo "[integration] Results: 0 passed, 0 failed, 0 total (skipped)"
  echo "[e2e] Results: 0 passed, 0 failed, 0 total (skipped)"
  echo "[propagate] test pyramid complete (all tiers skipped — submodule unavailable)"
  finish "skip" "skip_submodule_unavailable" \
    "prompts submodule unavailable; skipped propagation pyramid" 0
fi

overall_exit=0

if ! run_tier "unit" "70%" "${TEST_TIERS_DIR}/test-propagate-unit.sh"; then
  overall_exit=1
fi

if ! run_tier "integration" "20%" "${TEST_TIERS_DIR}/test-propagate-integration.sh"; then
  overall_exit=1
fi

if ! run_tier "e2e" "10%" "${TEST_TIERS_DIR}/test-propagate-e2e.sh"; then
  overall_exit=1
fi

echo ""
if [[ "${overall_exit}" -eq 0 ]]; then
  echo "[propagate] test pyramid complete"
  log_event "info" "propagate.finish" "Propagation test pyramid passed" outcome "pass_all_tiers"
  finish "pass" "pass_all_tiers" "Propagation test pyramid passed" 0
fi

echo "[propagate] test pyramid complete (${TIERS_FAILED} tier(s) failed)"
log_event "error" "propagate.finish" "Propagation test pyramid failed" \
  outcome "fail_tier_failures" \
  tiers_failed "#int:${TIERS_FAILED}"
finish "fail" "fail_tier_failures" \
  "Propagation test pyramid failed (${TIERS_FAILED} tier(s) failed)" 1
