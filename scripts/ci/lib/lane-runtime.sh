#!/usr/bin/env bash
set -Eeuo pipefail

# Shared runtime helpers for CI lanes with JSONL logging and idempotent artifacts.
# Uses ci_json_obj() for all JSON generation — no hand-rolled string concatenation.

# Source shared CI primitives (ci_json_escape, ci_json_obj, ci_now_utc, ci_epoch).
_lane_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../lib/ci-common.sh
source "${_lane_lib_dir}/../../lib/ci-common.sh"

lane_init() {
  local lane="${1:?lane name required}"
  local root="${2:-.}"

  CI_LANE_NAME="${lane}"
  CI_REPO_ROOT="${root}"
  CI_LANE_DIR="${CI_REPO_ROOT}/outputs/ci/${CI_LANE_NAME}"
  CI_LANE_REPORT="${CI_LANE_DIR}/report.json"
  CI_LANE_METRICS="${CI_LANE_DIR}/metrics.prom"
  CI_LANE_EVENTS="${CI_LANE_DIR}/events.jsonl"
  CI_LANE_START_EPOCH="$(ci_epoch)"
  CI_LANE_RUN_ID="$(ci_now_utc | tr -d ':T-' | cut -c1-15)Z-$$"
  CI_LANE_STAGE="bootstrap"
  CI_LANE_STEP_SEQ=0
  CI_LANE_FAILED_STAGE="none"
  CI_LANE_FAILED_COMMAND=""
  CI_LANE_FAILED_LINE=0
  CI_LANE_FAILED_EXIT=0
  CI_LANE_LOCK_FD=""

  mkdir -p "${CI_LANE_DIR}"
  : > "${CI_LANE_EVENTS}"
}

lane_acquire_lock() {
  local lock_file="${CI_LANE_DIR}/.lock"
  if command -v flock >/dev/null 2>&1; then
    exec {CI_LANE_LOCK_FD}>"${lock_file}"
    if ! flock -n "${CI_LANE_LOCK_FD}"; then
      echo "${CI_LANE_NAME}: already running (lock: ${lock_file})" >&2
      exit 1
    fi
    return
  fi
  echo "WARN: flock not found; continuing without lane lock (${CI_LANE_NAME})" >&2
}

_lane_release_lock() {
  if [[ -n "${CI_LANE_LOCK_FD:-}" ]]; then
    eval "exec ${CI_LANE_LOCK_FD}>&-" 2>/dev/null || true
    CI_LANE_LOCK_FD=""
  fi
}

lane_log() {
  local level="${1:-INFO}"
  local event="${2:-event}"
  local message="${3:-}"
  local stage="${4:-${CI_LANE_STAGE}}"
  local exit_code="${5:-0}"
  local line="${6:-0}"
  local cmd="${7:-}"

  local payload
  payload="$(ci_json_obj \
    ts             "$(ci_now_utc)" \
    run_id         "${CI_LANE_RUN_ID}" \
    lane           "${CI_LANE_NAME}" \
    level          "${level}" \
    event          "${event}" \
    stage          "${stage}" \
    exit_code      "#int:${exit_code}" \
    line           "#int:${line}" \
    failed_command "${cmd}" \
    message        "${message}")"
  printf '%s\n' "${payload}"
  printf '%s\n' "${payload}" >> "${CI_LANE_EVENTS}"
}

lane_run_step() {
  local name="${1:?step name required}"
  shift
  CI_LANE_STEP_SEQ=$((CI_LANE_STEP_SEQ + 1))
  CI_LANE_STAGE="${name}"
  lane_log "INFO" "lane.step.start" "Running step ${name} (#${CI_LANE_STEP_SEQ})" "${name}"
  "$@"
  lane_log "INFO" "lane.step.finish" "Step ${name} completed (#${CI_LANE_STEP_SEQ})" "${name}"
}

lane_emit_base_metrics() {
  local status="${1:?status required}"
  local duration="${2:?duration required}"
  local failure_count="0"
  if [[ "${status}" != "pass" ]]; then
    failure_count="1"
  fi

  cat > "${CI_LANE_METRICS}" <<EOF_METRICS
# TYPE ci_lane_status gauge
ci_lane_status{lane="${CI_LANE_NAME}",status="${status}"} 1
# TYPE ci_lane_duration_seconds gauge
ci_lane_duration_seconds{lane="${CI_LANE_NAME}"} ${duration}
# TYPE ci_lane_stage_failures_total counter
ci_lane_stage_failures_total{lane="${CI_LANE_NAME}",stage="${CI_LANE_FAILED_STAGE}"} ${failure_count}
# TYPE ci_lane_last_run_timestamp_seconds gauge
ci_lane_last_run_timestamp_seconds{lane="${CI_LANE_NAME}"} ${CI_LANE_START_EPOCH}
EOF_METRICS

  if [[ -n "${CI_LANE_EXTRA_METRICS:-}" ]]; then
    printf '%s\n' "${CI_LANE_EXTRA_METRICS}" >> "${CI_LANE_METRICS}"
  fi
}

lane_finish() {
  local status="${1:?status required}"
  local message="${2:?message required}"
  local exit_code="${3:?exit code required}"

  # Prevent recursive ERR trap firing if lane_finish itself fails.
  trap - ERR

  local end_epoch duration level
  end_epoch="$(ci_epoch)"
  duration="$((end_epoch - CI_LANE_START_EPOCH))"
  level="INFO"
  if [[ "${status}" != "pass" ]]; then
    level="ERROR"
  fi

  lane_log "${level}" "lane.finish" "${message}" "${CI_LANE_STAGE}" "${exit_code}" "${CI_LANE_FAILED_LINE}" "${CI_LANE_FAILED_COMMAND}"

  # Build report using ci_json_obj for safe JSON generation.
  # Extra fields are passed via CI_LANE_EXTRA_REPORT_FIELDS (key=value pairs).
  local report_json
  local -a extra_args=()
  if [[ -n "${CI_LANE_EXTRA_REPORT_FIELDS:-}" ]]; then
    local pair
    while IFS= read -r pair; do
      [[ -n "${pair}" ]] || continue
      local k="${pair%%=*}" v="${pair#*=}"
      extra_args+=("${k}" "${v}")
    done <<< "${CI_LANE_EXTRA_REPORT_FIELDS}"
  fi

  report_json="$(ci_json_obj \
    ts               "$(ci_now_utc)" \
    run_id           "${CI_LANE_RUN_ID}" \
    lane             "${CI_LANE_NAME}" \
    status           "${status}" \
    exit_code        "#int:${exit_code}" \
    stage            "${CI_LANE_FAILED_STAGE}" \
    line             "#int:${CI_LANE_FAILED_LINE}" \
    failed_command   "${CI_LANE_FAILED_COMMAND}" \
    duration_seconds "#int:${duration}" \
    steps_executed   "#int:${CI_LANE_STEP_SEQ}" \
    message          "${message}" \
    "${extra_args[@]}")"

  printf '%s\n' "${report_json}" > "${CI_LANE_REPORT}"

  lane_emit_base_metrics "${status}" "${duration}"
  _lane_release_lock
  exit "${exit_code}"
}

lane_on_err() {
  local exit_code="$?"
  local line="${1:-0}"
  local cmd="${2:-unknown}"
  CI_LANE_FAILED_STAGE="${CI_LANE_STAGE}"
  CI_LANE_FAILED_COMMAND="${cmd}"
  CI_LANE_FAILED_LINE="${line}"
  export CI_LANE_FAILED_EXIT="${exit_code}"
  lane_finish "fail" "${CI_LANE_NAME} failed at stage ${CI_LANE_STAGE} line ${line}" "${exit_code}"
}
