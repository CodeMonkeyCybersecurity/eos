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
  # Strip control characters (U+0000-U+001F, U+007F) except \n \r \t
  # which we escape explicitly below.  Per RFC 8259 Section 7, all control
  # characters MUST be escaped or removed in JSON strings.
  value="$(printf '%s' "${value}" | tr -d '\001-\010\013\014\016-\037\177')"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

# ci_json_obj builds a valid JSON object from key=value arguments.
# Uses jq when available, falls back to python3.
# All values are strings by default. Prefix a value with #int: to emit
# it as a JSON integer (e.g., ci_json_obj exit_code '#int:0').
# Usage: ci_json_obj key1 val1 key2 val2 ...
ci_json_obj() {
  if command -v jq >/dev/null 2>&1; then
    _ci_json_obj_jq "$@"
  elif command -v python3 >/dev/null 2>&1; then
    _ci_json_obj_python "$@"
  else
    printf 'ERROR: ci_json_obj requires jq or python3\n' >&2
    return 1
  fi
}

_ci_json_obj_jq() {
  local args=()
  while [[ $# -ge 2 ]]; do
    local key="${1}" val="${2}"
    shift 2
    if [[ "${val}" == '#int:'* ]]; then
      args+=(--argjson "${key}" "${val#'#int:'}")
    else
      args+=(--arg "${key}" "${val}")
    fi
  done
  jq -n -c "${args[@]}" '$ARGS.named'
}

_ci_json_obj_python() {
  local pairs=()
  while [[ $# -ge 2 ]]; do
    pairs+=("${1}" "${2}")
    shift 2
  done
  python3 -c "import json,sys;p=sys.argv[1:];d={};exec('for i in range(0,len(p),2):\\n d[p[i]]=int(p[i+1][5:]) if p[i+1].startswith(\"#int:\") else p[i+1]');print(json.dumps(d,ensure_ascii=True))" "${pairs[@]}"
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
