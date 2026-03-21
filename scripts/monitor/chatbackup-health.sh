#!/usr/bin/env bash
set -euo pipefail

status_file="${1:-${HOME}/.eos/restic/chat-archive-status.json}"
max_age_hours="${MAX_AGE_HOURS:-24}"

if ! command -v jq >/dev/null 2>&1; then
  echo "CRITICAL: jq is required to parse ${status_file}" >&2
  exit 2
fi

if [[ ! -f "${status_file}" ]]; then
  echo "CRITICAL: status file not found: ${status_file}" >&2
  exit 2
fi

last_success="$(jq -r '.last_success // ""' "${status_file}")"
last_failure="$(jq -r '.last_failure // ""' "${status_file}")"
last_attempt="$(jq -r '.last_attempt // ""' "${status_file}")"
last_run_state="$(jq -r '.last_run_state // ""' "${status_file}")"
last_error="$(jq -r '.last_error // ""' "${status_file}")"
success_count="$(jq -r '.success_count // 0' "${status_file}")"
failure_count="$(jq -r '.failure_count // 0' "${status_file}")"
tools_found="$(jq -r '(.tools_found // []) | join(",")' "${status_file}")"
users_scanned="$(jq -r '(.users_scanned // []) | join(",")' "${status_file}")"

parse_epoch() {
  local timestamp="${1:-}"
  if [[ -z "${timestamp}" ]]; then
    return 0
  fi
  date -d "${timestamp}" +%s 2>/dev/null || return 1
}

if [[ "${last_run_state}" == "failure" ]]; then
  echo "CRITICAL: latest backup run failed at ${last_failure:-unknown} error=${last_error:-unknown} failures=${failure_count} users=${users_scanned} tools=${tools_found}" >&2
  exit 2
fi

if [[ -z "${last_success}" ]]; then
  if [[ "${last_run_state}" == "noop" ]]; then
    echo "WARNING: backup ran but found no AI tool data yet (last_attempt=${last_attempt:-unknown}, users=${users_scanned}, failures=${failure_count})"
    exit 1
  fi
  echo "CRITICAL: no successful backup recorded yet (failures=${failure_count})" >&2
  exit 2
fi

last_success_epoch="$(parse_epoch "${last_success}" || true)"
if [[ -z "${last_success_epoch}" ]]; then
  echo "CRITICAL: invalid last_success timestamp in ${status_file}: ${last_success}" >&2
  exit 2
fi

now_epoch="$(date +%s)"
age_hours="$(( (now_epoch - last_success_epoch) / 3600 ))"

if (( age_hours > max_age_hours )); then
  echo "CRITICAL: last_success=${last_success} (${age_hours}h old, threshold=${max_age_hours}h) failures=${failure_count}" >&2
  exit 2
fi

last_failure_epoch="$(parse_epoch "${last_failure}" || true)"
if [[ -n "${last_failure_epoch}" ]] && (( last_failure_epoch > last_success_epoch )); then
  echo "WARNING: latest failure is newer than latest success (last_failure=${last_failure}, error=${last_error:-unknown}, successes=${success_count}, failures=${failure_count}, users=${users_scanned}, tools=${tools_found})"
  exit 1
fi

echo "OK: last_success=${last_success} (${age_hours}h old), state=${last_run_state:-success}, successes=${success_count}, failures=${failure_count}, users=${users_scanned}, tools=${tools_found}"
