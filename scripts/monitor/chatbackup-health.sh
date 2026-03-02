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
success_count="$(jq -r '.success_count // 0' "${status_file}")"
failure_count="$(jq -r '.failure_count // 0' "${status_file}")"
tools_found="$(jq -r '(.tools_found // []) | join(",")' "${status_file}")"

if [[ -z "${last_success}" ]]; then
  echo "CRITICAL: no successful backup recorded yet (failures=${failure_count})" >&2
  exit 2
fi

last_success_epoch="$(date -d "${last_success}" +%s 2>/dev/null || true)"
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

if (( failure_count > 0 )) && [[ -n "${last_failure}" ]]; then
  echo "WARNING: backup healthy but failures recorded (successes=${success_count}, failures=${failure_count}, last_failure=${last_failure}, tools=${tools_found})"
  exit 1
fi

echo "OK: last_success=${last_success} (${age_hours}h old), successes=${success_count}, failures=${failure_count}, tools=${tools_found}"
