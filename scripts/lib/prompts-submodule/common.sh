#!/usr/bin/env bash
set -Eeuo pipefail

PS_SCHEMA_VERSION="2"

# Alias: ps_normalize_bool is used by tests exercising the normalization path.
ps_normalize_bool() { ci_normalize_bool "$@"; }

ps_schema_version() {
  printf '%s' "${PS_SCHEMA_VERSION}"
}

ps_normalize_strict_remote() {
  local value
  value="$(printf '%s' "${1:-auto}" | tr '[:upper:]' '[:lower:]')"
  case "${value}" in
    true|false|auto)
      printf '%s' "${value}"
      ;;
    *)
      printf 'auto'
      ;;
  esac
}

ps_repo_root() {
  local script_path="${1:?script path required}"
  cd "$(dirname "${script_path}")/.." && pwd
}

