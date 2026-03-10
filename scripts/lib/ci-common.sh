#!/usr/bin/env bash
# Shared primitives for CI lane and prompts-submodule libraries.
# Both lane-runtime.sh and prompts-submodule.sh source this file.
# Keep this minimal: only truly shared, stable helpers belong here.
set -Eeuo pipefail

# Guard against double-sourcing.
if [[ -n "${_CI_COMMON_LOADED:-}" ]]; then
  return 0
fi
_CI_COMMON_LOADED=1

ci_json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

ci_now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

ci_epoch() {
  date +%s
}

ci_in_ci() {
  [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" || -n "${GITEA_ACTIONS:-}" ]]
}

ci_normalize_bool() {
  local v
  v="$(printf '%s' "${1:-false}" | tr '[:upper:]' '[:lower:]')"
  case "${v}" in
    true|1|yes|y|on) printf 'true' ;;
    *) printf 'false' ;;
  esac
}
