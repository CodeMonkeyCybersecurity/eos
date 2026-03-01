#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
# shellcheck source=../lib/git-env.sh
source "${script_dir}/../lib/git-env.sh"

lane_dir="outputs/ci/debug"
mkdir -p "${lane_dir}"
report="${lane_dir}/report.json"
metrics="${lane_dir}/metrics.prom"
events="${lane_dir}/events.jsonl"
start_epoch="$(date +%s)"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"

current_stage="bootstrap"
failed_stage="none"
failed_command=""
failed_line=0
failed_exit_code=0

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

acquire_lock() {
  local lock_file="${lane_dir}/.lock"
  if command -v flock >/dev/null 2>&1; then
    exec {lock_fd}>"${lock_file}"
    if ! flock -n "${lock_fd}"; then
      echo "ci:debug already running (lock: ${lock_file})" >&2
      exit 1
    fi
    return
  fi

  # Fallback when flock is unavailable; execution remains valid but unlocked.
  echo "WARN: flock not found; running without ci:debug artifact lock" >&2
}

init_artifacts() {
  : > "${events}"
}

log_json() {
  local level="${1:-INFO}"
  local event="${2:-event}"
  local message="${3:-}"
  local stage="${4:-${current_stage}}"
  local exit_code="${5:-0}"
  local line="${6:-0}"
  local cmd="${7:-}"

  local payload
  payload="{\"ts\":\"$(now_utc)\",\"run_id\":\"$(json_escape "${run_id}")\",\"level\":\"$(json_escape "${level}")\",\"event\":\"$(json_escape "${event}")\",\"stage\":\"$(json_escape "${stage}")\",\"exit_code\":${exit_code},\"line\":${line},\"failed_command\":\"$(json_escape "${cmd}")\",\"message\":\"$(json_escape "${message}")\"}"
  printf '%s\n' "${payload}"
  printf '%s\n' "${payload}" >> "${events}"
}

emit_metrics() {
  local status="${1:?status required}"
  local duration="${2:?duration required}"
  local failure_count="0"
  if [[ "${status}" != "pass" ]]; then
    failure_count="1"
  fi

  cat > "${metrics}" <<EOF_METRICS
# TYPE ci_debug_status gauge
ci_debug_status{status="${status}"} 1
# TYPE ci_debug_duration_seconds gauge
ci_debug_duration_seconds ${duration}
# TYPE ci_debug_stage_failures_total counter
ci_debug_stage_failures_total{stage="${failed_stage}"} ${failure_count}
# TYPE ci_debug_last_run_timestamp_seconds gauge
ci_debug_last_run_timestamp_seconds ${start_epoch}
EOF_METRICS
}

finish() {
  local status="${1:?status required}"
  local message="${2:?message required}"
  local exit_code="${3:?exit code required}"

  trap - ERR

  local end_epoch duration level
  end_epoch="$(date +%s)"
  duration="$((end_epoch - start_epoch))"

  level="INFO"
  if [[ "${status}" != "pass" ]]; then
    level="ERROR"
  fi

  log_json "${level}" "ci_debug.finish" "${message}" "${current_stage}" "${exit_code}" "${failed_line}" "${failed_command}"

  cat > "${report}" <<JSON
{
  "ts": "$(json_escape "$(now_utc)")",
  "run_id": "$(json_escape "${run_id}")",
  "lane": "ci-debug",
  "status": "$(json_escape "${status}")",
  "exit_code": ${exit_code},
  "stage": "$(json_escape "${failed_stage}")",
  "line": ${failed_line},
  "failed_command": "$(json_escape "${failed_command}")",
  "duration_seconds": ${duration},
  "message": "$(json_escape "${message}")"
}
JSON

  emit_metrics "${status}" "${duration}"
  exit "${exit_code}"
}

on_err() {
  local exit_code="$?"
  local line="${1:-0}"
  local cmd="${2:-unknown}"

  failed_stage="${current_stage}"
  failed_command="${cmd}"
  failed_line="${line}"
  failed_exit_code="${exit_code}"

  finish "fail" "ci:debug failed at stage ${current_stage} line ${line}" "${exit_code}"
}

run_step() {
  local name="${1:?step name required}"
  shift

  current_stage="${name}"
  log_json "INFO" "ci_debug.step.start" "Running step ${name}" "${name}"
  "$@"
  log_json "INFO" "ci_debug.step.finish" "Step ${name} completed" "${name}"
}

trap 'on_err "${LINENO}" "${BASH_COMMAND}"' ERR

acquire_lock
init_artifacts
log_json "INFO" "ci_debug.start" "Starting ci:debug parity lane" "bootstrap"

run_step "policy_validate" go run ./test/ci/tool policy-validate test/ci/suites.yaml
run_step "preflight" scripts/ci/preflight.sh
run_step "sanitize_git_env" ge_unset_git_local_env

export PATH="$(go env GOPATH)/bin:${PATH}"
if ! command -v golangci-lint >/dev/null 2>&1; then
  log_json "INFO" "ci_debug.bootstrap" "golangci-lint missing; installing pinned v2.0.0" "bootstrap"
  run_step "install_golangci_lint" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.0.0
fi

export CI_EVENT_NAME="${CI_EVENT_NAME:-pull_request}"
export CI_BASE_REF="${CI_BASE_REF:-main}"
if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" || -n "${GITEA_ACTIONS:-}" ]]; then
  run_step "lint_changed" scripts/ci/lint.sh changed
else
  current_stage="local_lint"
  changed_go_files="$(git diff --cached --name-only --diff-filter=ACMR -- '*.go' | grep -v '^vendor/' || true)"
  if [[ -z "${changed_go_files}" ]]; then
    changed_go_files="$(git diff --name-only --diff-filter=ACMR -- '*.go' | grep -v '^vendor/' || true)"
  fi

  if [[ -n "${changed_go_files}" ]]; then
    log_json "INFO" "ci_debug.local_lint" "Running local changed-file lint" "local_lint"
    unformatted="$(echo "${changed_go_files}" | xargs -r gofmt -s -l)"
    if [[ -n "${unformatted}" ]]; then
      failed_stage="local_lint"
      failed_command="gofmt -s -l changed_go_files"
      failed_line=0
      finish "fail" "gofmt check failed for changed Go files" 1
    fi

    local_base="$(git merge-base HEAD "${CI_BASE_REF}" 2>/dev/null || git rev-parse "${CI_BASE_REF}" 2>/dev/null || echo "")"
    if [[ -n "${local_base}" ]]; then
      run_step "lint_changed" golangci-lint run --timeout=8m --config=.golangci.yml --new-from-rev="${local_base}"
    else
      changed_pkgs="$(echo "${changed_go_files}" | xargs -n1 dirname | sort -u | sed 's|^|./|')"
      run_step "lint_changed_fallback" bash -c 'echo "$1" | xargs -r golangci-lint run --timeout=8m --config=.golangci.yml' _ "${changed_pkgs}"
    fi
  else
    log_json "INFO" "ci_debug.local_lint" "No changed Go files detected; skipping local lint" "local_lint"
  fi
fi

run_step "compile_smoke" go test -run '^$' ./cmd/...
run_step "submodule_freshness_pyramid" bash test/ci/test-submodule-freshness.sh
run_step "governance_wrapper_tests" bash test/ci/test-governance-check.sh

failed_stage="none"
failed_command=""
failed_line=0
failed_exit_code=0
current_stage="complete"
finish "pass" "ci:debug completed successfully" 0
