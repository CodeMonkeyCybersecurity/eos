#!/usr/bin/env bash
set -Eeuo pipefail

# Shared runtime helpers for CI lanes with JSONL logging and idempotent artifacts.

lane_init() {
  local lane="${1:?lane name required}"
  local root="${2:-.}"

  CI_LANE_NAME="${lane}"
  CI_REPO_ROOT="${root}"
  CI_LANE_DIR="${CI_REPO_ROOT}/outputs/ci/${CI_LANE_NAME}"
  CI_LANE_REPORT="${CI_LANE_DIR}/report.json"
  CI_LANE_METRICS="${CI_LANE_DIR}/metrics.prom"
  CI_LANE_EVENTS="${CI_LANE_DIR}/events.jsonl"
  CI_LANE_START_EPOCH="$(date +%s)"
  CI_LANE_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  CI_LANE_STAGE="bootstrap"
  CI_LANE_FAILED_STAGE="none"
  CI_LANE_FAILED_COMMAND=""
  CI_LANE_FAILED_LINE=0
  CI_LANE_FAILED_EXIT=0

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

lane_json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

lane_now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
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
  payload="{\"ts\":\"$(lane_now_utc)\",\"run_id\":\"$(lane_json_escape "${CI_LANE_RUN_ID}")\",\"lane\":\"$(lane_json_escape "${CI_LANE_NAME}")\",\"level\":\"$(lane_json_escape "${level}")\",\"event\":\"$(lane_json_escape "${event}")\",\"stage\":\"$(lane_json_escape "${stage}")\",\"exit_code\":${exit_code},\"line\":${line},\"failed_command\":\"$(lane_json_escape "${cmd}")\",\"message\":\"$(lane_json_escape "${message}")\"}"
  printf '%s\n' "${payload}"
  printf '%s\n' "${payload}" >> "${CI_LANE_EVENTS}"
}

lane_run_step() {
  local name="${1:?step name required}"
  shift
  CI_LANE_STAGE="${name}"
  lane_log "INFO" "lane.step.start" "Running step ${name}" "${name}"
  "$@"
  lane_log "INFO" "lane.step.finish" "Step ${name} completed" "${name}"
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

  trap - ERR

  local end_epoch duration level
  end_epoch="$(date +%s)"
  duration="$((end_epoch - CI_LANE_START_EPOCH))"
  level="INFO"
  if [[ "${status}" != "pass" ]]; then
    level="ERROR"
  fi

  lane_log "${level}" "lane.finish" "${message}" "${CI_LANE_STAGE}" "${exit_code}" "${CI_LANE_FAILED_LINE}" "${CI_LANE_FAILED_COMMAND}"

  cat > "${CI_LANE_REPORT}" <<EOF_REPORT
{
  "ts": "$(lane_json_escape "$(lane_now_utc)")",
  "run_id": "$(lane_json_escape "${CI_LANE_RUN_ID}")",
  "lane": "$(lane_json_escape "${CI_LANE_NAME}")",
  "status": "$(lane_json_escape "${status}")",
  "exit_code": ${exit_code},
  "stage": "$(lane_json_escape "${CI_LANE_FAILED_STAGE}")",
  "line": ${CI_LANE_FAILED_LINE},
  "failed_command": "$(lane_json_escape "${CI_LANE_FAILED_COMMAND}")",
  "duration_seconds": ${duration},
  ${CI_LANE_REPORT_EXTRA_JSON:-"\"extra\":null"},
  "message": "$(lane_json_escape "${message}")"
}
EOF_REPORT

  lane_emit_base_metrics "${status}" "${duration}"
  exit "${exit_code}"
}

lane_on_err() {
  local exit_code="$?"
  local line="${1:-0}"
  local cmd="${2:-unknown}"
  CI_LANE_FAILED_STAGE="${CI_LANE_STAGE}"
  CI_LANE_FAILED_COMMAND="${cmd}"
  CI_LANE_FAILED_LINE="${line}"
  CI_LANE_FAILED_EXIT="${exit_code}"
  lane_finish "fail" "${CI_LANE_NAME} failed at stage ${CI_LANE_STAGE} line ${line}" "${exit_code}"
}
