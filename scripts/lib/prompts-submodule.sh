#!/usr/bin/env bash
set -euo pipefail

ps_json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

ps_now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

ps_in_ci() {
  [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" || -n "${GITEA_ACTIONS:-}" ]]
}

ps_normalize_bool() {
  local v
  v="$(printf '%s' "${1:-false}" | tr '[:upper:]' '[:lower:]')"
  case "${v}" in
    true|1|yes|y|on)
      printf 'true'
      ;;
    *)
      printf 'false'
      ;;
  esac
}

ps_normalize_strict_remote() {
  local v
  v="$(printf '%s' "${1:-auto}" | tr '[:upper:]' '[:lower:]')"
  case "${v}" in
    true|false|auto)
      printf '%s' "${v}"
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

ps_prompts_submodule_path() {
  local repo_root="${1:?repo root required}"
  if [[ ! -f "${repo_root}/.gitmodules" ]]; then
    return 1
  fi

  local entries key path
  entries="$(git -C "${repo_root}" config -f .gitmodules --get-regexp '^submodule\..*\.path$' 2>/dev/null || true)"
  if [[ -z "${entries}" ]]; then
    return 1
  fi

  while read -r key path; do
    case "${path}" in
      prompts|third_party/prompts)
        printf '%s\n' "${path}"
        return 0
        ;;
    esac
  done <<< "${entries}"
  return 1
}

ps_prompts_submodule_name() {
  local repo_root="${1:?repo root required}"
  local submodule_path="${2:?submodule path required}"
  local entries key path name

  entries="$(git -C "${repo_root}" config -f .gitmodules --get-regexp '^submodule\..*\.path$' 2>/dev/null || true)"
  if [[ -z "${entries}" ]]; then
    return 1
  fi

  while read -r key path; do
    if [[ "${path}" == "${submodule_path}" ]]; then
      name="${key#submodule.}"
      name="${name%.path}"
      printf '%s\n' "${name}"
      return 0
    fi
  done <<< "${entries}"
  return 1
}

ps_prompts_submodule_initialized() {
  local repo_root="${1:?repo root required}"
  local submodule_path="${2:?submodule path required}"
  local status_line

  status_line="$(git -C "${repo_root}" submodule status -- "${submodule_path}" 2>/dev/null || true)"
  if [[ -z "${status_line}" ]]; then
    return 1
  fi
  [[ "${status_line:0:1}" != "-" ]]
}

ps_tracking_branch() {
  local repo_root="${1:?repo root required}"
  local submodule_path="${2:?submodule path required}"
  local submodule_name branch

  submodule_name="$(ps_prompts_submodule_name "${repo_root}" "${submodule_path}" || true)"
  branch=""
  if [[ -n "${submodule_name}" ]]; then
    branch="$(git -C "${repo_root}" config -f .gitmodules --get "submodule.${submodule_name}.branch" 2>/dev/null || true)"
  fi
  if [[ "${branch}" == "." ]]; then
    branch="$(git -C "${repo_root}" symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
  fi
  if [[ -z "${branch}" ]]; then
    branch="main"
  fi
  printf '%s\n' "${branch}"
}

ps_should_strict_fail_remote() {
  local strict_remote="${1:-auto}"
  case "${strict_remote}" in
    true)
      return 0
      ;;
    false)
      return 1
      ;;
    auto)
      ps_in_ci
      return $?
      ;;
    *)
      ps_in_ci
      return $?
      ;;
  esac
}

ps_git_fetch_remote_branch() {
  local repo_path="${1:?repo path required}"
  local remote_branch="${2:?remote branch required}"
  local timeout_sec="${3:-20}"

  if command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=5s "${timeout_sec}s" \
      git -C "${repo_path}" fetch origin "${remote_branch}" --quiet --no-tags
    return $?
  fi
  git -C "${repo_path}" fetch origin "${remote_branch}" --quiet --no-tags
}

ps_submodule_has_local_changes() {
  local repo_root="${1:?repo root required}"
  local submodule_path="${2:?submodule path required}"

  [[ -n "$(git -C "${repo_root}/${submodule_path}" status --porcelain 2>/dev/null || true)" ]]
}

ps_outcome_known() {
  local kind="${1:?kind required}"
  local outcome="${2:?outcome required}"
  case "${kind}:${outcome}" in
    freshness:pass_up_to_date|freshness:pass_auto_updated|freshness:pass_auto_updated_worktree_only|freshness:fail_stale|freshness:fail_remote_unreachable|freshness:fail_missing_remote_ref|freshness:fail_corrupt_submodule|freshness:fail_checkout|freshness:fail_dirty_worktree|freshness:fail_internal|freshness:skip_not_registered|freshness:skip_uninitialized|freshness:skip_remote_unreachable|freshness:skip_missing_remote_ref)
      return 0
      ;;
    governance:pass_checked_direct|governance:pass_checked_via_symlink|governance:fail_checker_error|governance:skip_not_registered|governance:skip_uninitialized)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

ps_status_from_outcome() {
  local outcome="${1:?outcome required}"
  case "${outcome}" in
    pass_*)
      printf 'pass'
      ;;
    skip_*)
      printf 'skip'
      ;;
    fail_*)
      printf 'fail'
      ;;
    *)
      printf 'unknown'
      ;;
  esac
}

ps_log_json() {
  local level="${1:-INFO}"
  local event="${2:-event}"
  local outcome="${3:-unknown}"
  local message="${4:-}"
  local repo_root="${5:-}"
  local prompts_path="${6:-}"
  local local_sha="${7:-unknown}"
  local remote_sha="${8:-unknown}"
  local remote_branch="${9:-unknown}"
  local strict_remote="${10:-auto}"
  local auto_update="${11:-false}"
  printf '{"ts":"%s","level":"%s","event":"%s","outcome":"%s","status":"%s","repo_root":"%s","prompts_path":"%s","local_sha":"%s","remote_sha":"%s","remote_branch":"%s","strict_remote":"%s","auto_update":"%s","message":"%s"}\n' \
    "$(ps_now_utc)" \
    "$(ps_json_escape "${level}")" \
    "$(ps_json_escape "${event}")" \
    "$(ps_json_escape "${outcome}")" \
    "$(ps_status_from_outcome "${outcome}")" \
    "$(ps_json_escape "${repo_root}")" \
    "$(ps_json_escape "${prompts_path}")" \
    "$(ps_json_escape "${local_sha}")" \
    "$(ps_json_escape "${remote_sha}")" \
    "$(ps_json_escape "${remote_branch}")" \
    "$(ps_json_escape "${strict_remote}")" \
    "$(ps_json_escape "${auto_update}")" \
    "$(ps_json_escape "${message}")"
}

ps_write_json_report() {
  local report_path="${1:?report path required}"
  local kind="${2:?kind required}"
  local outcome="${3:?outcome required}"
  local message="${4:-}"
  local repo_root="${5:-}"
  local prompts_path="${6:-}"
  local local_sha="${7:-unknown}"
  local remote_sha="${8:-unknown}"
  local remote_branch="${9:-unknown}"
  local strict_remote="${10:-auto}"
  local auto_update="${11:-false}"
  local exit_code="${12:-0}"

  mkdir -p "$(dirname "${report_path}")"
  cat > "${report_path}" <<JSON
{
  "ts": "$(ps_json_escape "$(ps_now_utc)")",
  "kind": "$(ps_json_escape "${kind}")",
  "outcome": "$(ps_json_escape "${outcome}")",
  "status": "$(ps_json_escape "$(ps_status_from_outcome "${outcome}")")",
  "exit_code": ${exit_code},
  "repo_root": "$(ps_json_escape "${repo_root}")",
  "prompts_path": "$(ps_json_escape "${prompts_path}")",
  "local_sha": "$(ps_json_escape "${local_sha}")",
  "remote_sha": "$(ps_json_escape "${remote_sha}")",
  "remote_branch": "$(ps_json_escape "${remote_branch}")",
  "strict_remote": "$(ps_json_escape "${strict_remote}")",
  "auto_update": "$(ps_json_escape "${auto_update}")",
  "message": "$(ps_json_escape "${message}")"
}
JSON
}

ps_emit_prom_metrics() {
  local metrics_path="${1:-}"
  local outcome="${2:-unknown}"
  local strict_remote="${3:-auto}"
  if [[ -z "${metrics_path}" ]]; then
    return 0
  fi

  local stale_value=0
  if [[ "${outcome}" == "fail_stale" ]]; then
    stale_value=1
  fi

  mkdir -p "$(dirname "${metrics_path}")"
  cat > "${metrics_path}" <<EOF
# TYPE prompts_submodule_freshness_status gauge
prompts_submodule_freshness_status{outcome="${outcome}",strict_remote="${strict_remote}"} 1
# TYPE prompts_submodule_freshness_stale gauge
prompts_submodule_freshness_stale ${stale_value}
EOF
}

ps_log_level_for_outcome() {
  local outcome="${1:?outcome required}"
  case "$(ps_status_from_outcome "${outcome}")" in
    fail)
      printf 'ERROR'
      ;;
    skip)
      printf 'WARN'
      ;;
    *)
      printf 'INFO'
      ;;
  esac
}

ps_finish_and_exit() {
  local kind="${1:?kind required}"
  local outcome="${2:?outcome required}"
  local message="${3:?message required}"
  local exit_code="${4:?exit code required}"
  local report_path="${5:?report path required}"
  local metrics_path="${6:-}"
  local repo_root="${7:-}"
  local prompts_path="${8:-}"
  local local_sha="${9:-unknown}"
  local remote_sha="${10:-unknown}"
  local remote_branch="${11:-unknown}"
  local strict_remote="${12:-auto}"
  local auto_update="${13:-false}"

  if ! ps_outcome_known "${kind}" "${outcome}"; then
    if [[ "${kind}" == "freshness" ]]; then
      outcome="fail_internal"
    else
      outcome="fail_checker_error"
    fi
    message="FAIL: internal error - unknown outcome emitted"
    exit_code=1
  fi

  local level event
  level="$(ps_log_level_for_outcome "${outcome}")"
  event="${kind}_check.finish"

  ps_log_json "${level}" "${event}" "${outcome}" "${message}" "${repo_root}" "${prompts_path}" "${local_sha}" "${remote_sha}" "${remote_branch}" "${strict_remote}" "${auto_update}"
  ps_write_json_report "${report_path}" "${kind}" "${outcome}" "${message}" "${repo_root}" "${prompts_path}" "${local_sha}" "${remote_sha}" "${remote_branch}" "${strict_remote}" "${auto_update}" "${exit_code}"

  if [[ "${kind}" == "freshness" ]]; then
    ps_emit_prom_metrics "${metrics_path}" "${outcome}" "${strict_remote}"
  fi

  exit "${exit_code}"
}
