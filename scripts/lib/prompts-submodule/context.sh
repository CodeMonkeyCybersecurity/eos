#!/usr/bin/env bash
set -Eeuo pipefail

PS_CTX_KIND="${PS_CTX_KIND:-}"
PS_CTX_ACTION="${PS_CTX_ACTION:-}"
PS_CTX_REPORT_PATH="${PS_CTX_REPORT_PATH:-}"
PS_CTX_METRICS_PATH="${PS_CTX_METRICS_PATH:-}"
PS_CTX_EVENTS_PATH="${PS_CTX_EVENTS_PATH:-}"
PS_CTX_REPO_ROOT="${PS_CTX_REPO_ROOT:-}"
PS_CTX_PROMPTS_PATH="${PS_CTX_PROMPTS_PATH:-}"
PS_CTX_LOCAL_SHA="${PS_CTX_LOCAL_SHA:-unknown}"
PS_CTX_REMOTE_SHA="${PS_CTX_REMOTE_SHA:-unknown}"
PS_CTX_REMOTE_BRANCH="${PS_CTX_REMOTE_BRANCH:-unknown}"
PS_CTX_STRICT_REMOTE="${PS_CTX_STRICT_REMOTE:-auto}"
PS_CTX_AUTO_UPDATE="${PS_CTX_AUTO_UPDATE:-false}"
PS_CTX_ARTIFACT_WARNINGS="${PS_CTX_ARTIFACT_WARNINGS:-0}"
PS_CTX_RUN_ID="${PS_CTX_RUN_ID:-}"
PS_CTX_START_EPOCH="${PS_CTX_START_EPOCH:-0}"

ps_ctx_begin() {
  local kind="${1:?kind required}"
  local action="${2:?action required}"
  local report_path="${3:?report path required}"
  local metrics_path="${4:-}"
  local repo_root="${5:?repo root required}"
  local strict_remote="${6:-auto}"
  local auto_update="${7:-false}"

  PS_CTX_KIND="${kind}"
  PS_CTX_ACTION="${action}"
  PS_CTX_REPORT_PATH="${report_path}"
  PS_CTX_METRICS_PATH="${metrics_path}"
  PS_CTX_EVENTS_PATH="$(dirname "${report_path}")/events.jsonl"
  PS_CTX_REPO_ROOT="${repo_root}"
  PS_CTX_STRICT_REMOTE="${strict_remote}"
  PS_CTX_AUTO_UPDATE="${auto_update}"
  ps_ctx_init
}

ps_ctx_init() {
  if [[ -z "${PS_CTX_KIND:-}" ]]; then
    printf 'FAIL: PS_CTX_KIND must be set before calling ps_ctx_init\n' >&2
    return 1
  fi
  if [[ ! "${PS_CTX_KIND}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    printf 'FAIL: PS_CTX_KIND contains invalid characters for metric names: %s\n' "${PS_CTX_KIND}" >&2
    return 1
  fi
  if [[ -z "${PS_CTX_ACTION:-}" ]]; then
    printf 'FAIL: PS_CTX_ACTION must be set before calling ps_ctx_init\n' >&2
    return 1
  fi
  if [[ -z "${PS_CTX_REPORT_PATH:-}" ]]; then
    printf 'FAIL: PS_CTX_REPORT_PATH must be set before calling ps_ctx_init\n' >&2
    return 1
  fi

  PS_CTX_STRICT_REMOTE="$(ps_normalize_strict_remote "${PS_CTX_STRICT_REMOTE:-auto}")"
  PS_CTX_AUTO_UPDATE="$(ci_normalize_bool "${PS_CTX_AUTO_UPDATE:-false}")"
  PS_CTX_ARTIFACT_WARNINGS=0
  local _ps_first_init="false"
  if [[ -z "${PS_CTX_RUN_ID:-}" ]]; then
    _ps_first_init="true"
    PS_CTX_RUN_ID="$(ci_now_utc | tr -d ':T-' | cut -c1-15)Z-$$"
  fi
  PS_CTX_START_EPOCH="$(ci_epoch)"
  if [[ -z "${PS_CTX_EVENTS_PATH:-}" ]]; then
    PS_CTX_EVENTS_PATH="$(dirname "${PS_CTX_REPORT_PATH}")/events.jsonl"
  fi
  if [[ -n "${PS_CTX_EVENTS_PATH:-}" && "${_ps_first_init}" == "true" ]]; then
    if ! mkdir -p "$(dirname "${PS_CTX_EVENTS_PATH}")" 2>/dev/null || ! : > "${PS_CTX_EVENTS_PATH}" 2>/dev/null; then
      printf 'WARN: unable to initialize prompts-submodule events log at %s\n' "${PS_CTX_EVENTS_PATH}" >&2
      PS_CTX_EVENTS_PATH=""
    fi
  fi

  # Clear hook-exported git env vars so submodule git operations work
  # even when invoked from a pre-commit hook context.
  ge_unset_git_local_env
}

ps_ctx_require() {
  [[ -n "${PS_CTX_KIND:-}" ]] || return 1
  [[ -n "${PS_CTX_ACTION:-}" ]] || return 1
  [[ -n "${PS_CTX_REPORT_PATH:-}" ]] || return 1
}

ps_outcome_known() {
  local kind="${1:?kind required}"
  local outcome="${2:?outcome required}"
  case "${kind}:${outcome}" in
    freshness:pass_up_to_date|freshness:pass_auto_updated|freshness:pass_auto_updated_worktree_only|freshness:fail_stale|freshness:fail_diverged|freshness:fail_remote_unreachable|freshness:fail_missing_remote_ref|freshness:fail_corrupt_submodule|freshness:fail_checkout|freshness:fail_dirty_worktree|freshness:fail_internal|freshness:skip_not_registered|freshness:skip_uninitialized|freshness:skip_remote_unreachable|freshness:skip_missing_remote_ref)
      return 0
      ;;
    governance:pass_checked_direct|governance:pass_checked_via_override|governance:fail_checker_error|governance:skip_not_registered|governance:skip_uninitialized)
      return 0
      ;;
    hook:pass_no_staged_changes|hook:pass_ci_debug|hook:pass_ci_debug_self_update|hook:fail_checker_error|hook:skip_not_registered|hook:skip_uninitialized)
      return 0
      ;;
    hook_install:pass_installed|hook_install:fail_not_git_repo|hook_install:fail_install)
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
    pass_*)   printf 'pass' ;;
    skip_*)   printf 'skip' ;;
    fail_*)   printf 'fail' ;;
    pending)  printf 'pending' ;;
    *)        printf 'unknown' ;;
  esac
}
