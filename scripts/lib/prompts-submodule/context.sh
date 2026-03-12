#!/usr/bin/env bash
set -Eeuo pipefail

PS_CTX_KIND="${PS_CTX_KIND:-}"
PS_CTX_ACTION="${PS_CTX_ACTION:-}"
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
PS_CTX_RUN_ID="${PS_CTX_RUN_ID:-}"

ps_ctx_init() {
  if [[ -z "${PS_CTX_KIND:-}" ]]; then
    printf 'FAIL: PS_CTX_KIND must be set before calling ps_ctx_init\n' >&2
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
  if [[ -z "${PS_CTX_RUN_ID:-}" ]]; then
    PS_CTX_RUN_ID="$(ci_now_utc | tr -d ':T-' | cut -c1-15)Z-$$"
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
    freshness:pass_up_to_date|freshness:pass_auto_updated|freshness:pass_auto_updated_worktree_only|freshness:fail_stale|freshness:fail_remote_unreachable|freshness:fail_missing_remote_ref|freshness:fail_corrupt_submodule|freshness:fail_checkout|freshness:fail_dirty_worktree|freshness:fail_internal|freshness:skip_not_registered|freshness:skip_uninitialized|freshness:skip_remote_unreachable|freshness:skip_missing_remote_ref)
      return 0
      ;;
    governance:pass_checked_direct|governance:pass_checked_via_override|governance:fail_checker_error|governance:skip_not_registered|governance:skip_uninitialized)
      return 0
      ;;
    hook:pass_checked_direct|hook:pass_checked_via_override|hook:fail_checker_error|hook:skip_not_registered|hook:skip_uninitialized)
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

