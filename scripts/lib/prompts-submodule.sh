#!/usr/bin/env bash
set -euo pipefail

PS_CTX_KIND="${PS_CTX_KIND:-}"
PS_CTX_REPORT_PATH="${PS_CTX_REPORT_PATH:-}"
PS_CTX_METRICS_PATH="${PS_CTX_METRICS_PATH:-}"
PS_CTX_REPO_ROOT="${PS_CTX_REPO_ROOT:-}"
PS_CTX_PROMPTS_PATH="${PS_CTX_PROMPTS_PATH:-}"
PS_CTX_LOCAL_SHA="${PS_CTX_LOCAL_SHA:-unknown}"
PS_CTX_REMOTE_SHA="${PS_CTX_REMOTE_SHA:-unknown}"
PS_CTX_REMOTE_BRANCH="${PS_CTX_REMOTE_BRANCH:-unknown}"
PS_CTX_STRICT_REMOTE="${PS_CTX_STRICT_REMOTE:-auto}"
PS_CTX_AUTO_UPDATE="${PS_CTX_AUTO_UPDATE:-false}"
PS_CTX_ARTIFACT_WARNINGS="${PS_CTX_ARTIFACT_WARNINGS:-0}"

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

ps_ctx_init() {
  PS_CTX_KIND="${1:?kind required}"
  PS_CTX_REPORT_PATH="${2:?report path required}"
  PS_CTX_METRICS_PATH="${3:-}"
  PS_CTX_REPO_ROOT="${4:-}"
  PS_CTX_PROMPTS_PATH="${5:-}"
  PS_CTX_LOCAL_SHA="${6:-unknown}"
  PS_CTX_REMOTE_SHA="${7:-unknown}"
  PS_CTX_REMOTE_BRANCH="${8:-unknown}"
  PS_CTX_STRICT_REMOTE="$(ps_normalize_strict_remote "${9:-auto}")"
  PS_CTX_AUTO_UPDATE="$(ps_normalize_bool "${10:-false}")"
  PS_CTX_ARTIFACT_WARNINGS=0
}

ps_ctx_require() {
  [[ -n "${PS_CTX_KIND:-}" ]] || return 1
  [[ -n "${PS_CTX_REPORT_PATH:-}" ]] || return 1
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

  printf '{"ts":"%s","level":"%s","event":"%s","kind":"%s","outcome":"%s","status":"%s","repo_root":"%s","prompts_path":"%s","local_sha":"%s","remote_sha":"%s","remote_branch":"%s","strict_remote":"%s","auto_update":"%s","artifact_warnings":%s,"message":"%s"}\n' \
    "$(ps_now_utc)" \
    "$(ps_json_escape "${level}")" \
    "$(ps_json_escape "${event}")" \
    "$(ps_json_escape "${PS_CTX_KIND:-unknown}")" \
    "$(ps_json_escape "${outcome}")" \
    "$(ps_status_from_outcome "${outcome}")" \
    "$(ps_json_escape "${PS_CTX_REPO_ROOT:-}")" \
    "$(ps_json_escape "${PS_CTX_PROMPTS_PATH:-}")" \
    "$(ps_json_escape "${PS_CTX_LOCAL_SHA:-unknown}")" \
    "$(ps_json_escape "${PS_CTX_REMOTE_SHA:-unknown}")" \
    "$(ps_json_escape "${PS_CTX_REMOTE_BRANCH:-unknown}")" \
    "$(ps_json_escape "${PS_CTX_STRICT_REMOTE:-auto}")" \
    "$(ps_json_escape "${PS_CTX_AUTO_UPDATE:-false}")" \
    "${PS_CTX_ARTIFACT_WARNINGS:-0}" \
    "$(ps_json_escape "${message}")"
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

ps_warn_artifact_failure() {
  local artifact_kind="${1:?artifact kind required}"
  local artifact_path="${2:-unknown}"
  local detail="${3:-unknown error}"

  PS_CTX_ARTIFACT_WARNINGS=$((PS_CTX_ARTIFACT_WARNINGS + 1))
  printf '{"ts":"%s","level":"WARN","event":"%s.artifact_warning","kind":"%s","artifact":"%s","path":"%s","message":"%s"}\n' \
    "$(ps_now_utc)" \
    "$(ps_json_escape "${PS_CTX_KIND:-unknown}")" \
    "$(ps_json_escape "${PS_CTX_KIND:-unknown}")" \
    "$(ps_json_escape "${artifact_kind}")" \
    "$(ps_json_escape "${artifact_path}")" \
    "$(ps_json_escape "${detail}")" >&2
}

ps_write_atomic_file() {
  local target_path="${1:?target path required}"
  local tmp_path

  mkdir -p "$(dirname "${target_path}")" || return 1
  tmp_path="$(mktemp "${target_path}.tmp.XXXXXX")" || return 1
  cat > "${tmp_path}" || {
    rm -f "${tmp_path}"
    return 1
  }
  mv -f "${tmp_path}" "${target_path}" || {
    rm -f "${tmp_path}"
    return 1
  }
}

ps_write_json_report() {
  local report_path="${1:?report path required}"
  local outcome="${2:?outcome required}"
  local message="${3:-}"
  local exit_code="${4:-0}"

  if ! ps_ctx_require; then
    ps_warn_artifact_failure "report" "${report_path}" "context missing for report emission"
    return 1
  fi

  ps_write_atomic_file "${report_path}" <<JSON || {
{
  "ts": "$(ps_json_escape "$(ps_now_utc)")",
  "kind": "$(ps_json_escape "${PS_CTX_KIND}")",
  "outcome": "$(ps_json_escape "${outcome}")",
  "status": "$(ps_json_escape "$(ps_status_from_outcome "${outcome}")")",
  "exit_code": ${exit_code},
  "repo_root": "$(ps_json_escape "${PS_CTX_REPO_ROOT}")",
  "prompts_path": "$(ps_json_escape "${PS_CTX_PROMPTS_PATH}")",
  "local_sha": "$(ps_json_escape "${PS_CTX_LOCAL_SHA}")",
  "remote_sha": "$(ps_json_escape "${PS_CTX_REMOTE_SHA}")",
  "remote_branch": "$(ps_json_escape "${PS_CTX_REMOTE_BRANCH}")",
  "strict_remote": "$(ps_json_escape "${PS_CTX_STRICT_REMOTE}")",
  "auto_update": "$(ps_json_escape "${PS_CTX_AUTO_UPDATE}")",
  "artifact_warnings": ${PS_CTX_ARTIFACT_WARNINGS},
  "message": "$(ps_json_escape "${message}")"
}
JSON
    ps_warn_artifact_failure "report" "${report_path}" "failed to write JSON report"
    return 1
  }
}

ps_emit_prom_metrics() {
  local outcome="${1:-unknown}"
  if [[ -z "${PS_CTX_METRICS_PATH:-}" ]]; then
    return 0
  fi

  local stale_value=0
  local status_value=0
  case "$(ps_status_from_outcome "${outcome}")" in
    pass)
      status_value=1
      ;;
    skip)
      status_value=0
      ;;
    fail)
      status_value=-1
      ;;
  esac
  if [[ "${outcome}" == "fail_stale" ]]; then
    stale_value=1
  fi

  ps_write_atomic_file "${PS_CTX_METRICS_PATH}" <<EOF_METRICS || {
# TYPE prompts_submodule_freshness_status gauge
prompts_submodule_freshness_status{outcome="${outcome}",strict_remote="${PS_CTX_STRICT_REMOTE}"} ${status_value}
# TYPE prompts_submodule_freshness_stale gauge
prompts_submodule_freshness_stale ${stale_value}
# TYPE prompts_submodule_freshness_last_run_timestamp_seconds gauge
prompts_submodule_freshness_last_run_timestamp_seconds $(date -u +%s)
EOF_METRICS
    ps_warn_artifact_failure "metrics" "${PS_CTX_METRICS_PATH}" "failed to write Prometheus textfile"
    return 1
  }
}

ps_finish_and_exit() {
  local outcome="${1:?outcome required}"
  local message="${2:?message required}"
  local exit_code="${3:?exit code required}"

  if ! ps_ctx_require; then
    printf 'FAIL: prompts-submodule context missing (kind/report_path)\n' >&2
    exit 1
  fi

  if ! ps_outcome_known "${PS_CTX_KIND}" "${outcome}"; then
    if [[ "${PS_CTX_KIND}" == "freshness" ]]; then
      outcome="fail_internal"
    else
      outcome="fail_checker_error"
    fi
    message="FAIL: internal error - unknown outcome emitted"
    exit_code=1
  fi

  local level event
  level="$(ps_log_level_for_outcome "${outcome}")"
  event="${PS_CTX_KIND}_check.finish"

  ps_log_json "${level}" "${event}" "${outcome}" "${message}"
  ps_write_json_report "${PS_CTX_REPORT_PATH}" "${outcome}" "${message}" "${exit_code}" || true

  if [[ "${PS_CTX_KIND}" == "freshness" ]]; then
    ps_emit_prom_metrics "${outcome}" || true
  fi

  exit "${exit_code}"
}
