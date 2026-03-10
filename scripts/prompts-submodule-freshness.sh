#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/prompts-submodule.sh
source "${script_dir}/lib/prompts-submodule.sh"

repo_root="$(ps_repo_root "${BASH_SOURCE[0]}")"
fetch_timeout_sec="${SUBMODULE_FETCH_TIMEOUT_SEC:-20}"

# Set context vars directly, then call ps_ctx_init to normalize/validate.
PS_CTX_KIND="freshness"
PS_CTX_REPORT_PATH="${SUBMODULE_REPORT_JSON:-${repo_root}/outputs/ci/submodule-freshness/report.json}"
PS_CTX_METRICS_PATH="${SUBMODULE_METRICS_TEXTFILE:-}"
PS_CTX_REPO_ROOT="${repo_root}"
PS_CTX_STRICT_REMOTE="${STRICT_REMOTE:-auto}"
PS_CTX_AUTO_UPDATE="${AUTO_UPDATE:-false}"
ps_ctx_init
trap 'ps_finish_and_exit "fail_internal" "FAIL: unexpected script error at line ${LINENO}" 1' ERR

ps_log_json "INFO" "submodule_freshness.start" "skip_not_registered" "Starting prompts submodule freshness check"

PS_CTX_PROMPTS_PATH="$(ps_prompts_submodule_path "${repo_root}" || true)"
if [[ -z "${PS_CTX_PROMPTS_PATH}" ]]; then
  ps_finish_and_exit "skip_not_registered" "SKIP: no prompts submodule registered in .gitmodules - nothing to check" 0
fi

if ! ps_prompts_submodule_initialized "${repo_root}" "${PS_CTX_PROMPTS_PATH}"; then
  ps_finish_and_exit "skip_uninitialized" "SKIP: prompts submodule exists but is not initialized. Run: git submodule update --init --recursive -- ${PS_CTX_PROMPTS_PATH}" 0
fi

if ! PS_CTX_LOCAL_SHA="$(git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" rev-parse HEAD 2>/dev/null)"; then
  ps_finish_and_exit "fail_corrupt_submodule" "FAIL: cannot read HEAD for ${PS_CTX_PROMPTS_PATH}; submodule may be corrupt. Run: git submodule update --init --force -- ${PS_CTX_PROMPTS_PATH}" 1
fi

PS_CTX_REMOTE_BRANCH="$(ps_tracking_branch "${repo_root}" "${PS_CTX_PROMPTS_PATH}")"
if ! ps_git_fetch_remote_branch "${repo_root}/${PS_CTX_PROMPTS_PATH}" "${PS_CTX_REMOTE_BRANCH}" "${fetch_timeout_sec}" 2>/dev/null; then
  if ps_should_strict_fail_remote "${PS_CTX_STRICT_REMOTE}"; then
    ps_finish_and_exit "fail_remote_unreachable" "FAIL: cannot fetch origin/${PS_CTX_REMOTE_BRANCH} for ${PS_CTX_PROMPTS_PATH} while STRICT_REMOTE=${PS_CTX_STRICT_REMOTE}" 2
  fi
  ps_finish_and_exit "skip_remote_unreachable" "SKIP: cannot fetch origin/${PS_CTX_REMOTE_BRANCH} for ${PS_CTX_PROMPTS_PATH} (offline or auth issue)" 0
fi

if ! PS_CTX_REMOTE_SHA="$(git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" rev-parse "origin/${PS_CTX_REMOTE_BRANCH}" 2>/dev/null)"; then
  if ps_should_strict_fail_remote "${PS_CTX_STRICT_REMOTE}"; then
    ps_finish_and_exit "fail_missing_remote_ref" "FAIL: origin/${PS_CTX_REMOTE_BRANCH} not available for ${PS_CTX_PROMPTS_PATH}" 2
  fi
  ps_finish_and_exit "skip_missing_remote_ref" "SKIP: origin/${PS_CTX_REMOTE_BRANCH} not available for ${PS_CTX_PROMPTS_PATH}" 0
fi

ps_log_json "INFO" "submodule_freshness.compare" "pass_up_to_date" "Comparing local and remote SHA"

if [[ "${PS_CTX_LOCAL_SHA}" == "${PS_CTX_REMOTE_SHA}" ]]; then
  ps_finish_and_exit "pass_up_to_date" "PASS: prompts submodule is up to date" 0
fi

if [[ "${PS_CTX_AUTO_UPDATE}" != "true" ]]; then
  ps_finish_and_exit "fail_stale" "FAIL: prompts submodule is stale (${PS_CTX_LOCAL_SHA:0:7} != ${PS_CTX_REMOTE_SHA:0:7}). Run: git submodule update --remote -- ${PS_CTX_PROMPTS_PATH}" 1
fi

if ps_submodule_has_local_changes "${repo_root}" "${PS_CTX_PROMPTS_PATH}"; then
  ps_finish_and_exit "fail_dirty_worktree" "FAIL: ${PS_CTX_PROMPTS_PATH} has local changes; refusing auto-update. Commit/stash/reset submodule changes first." 1
fi

previous_sha="${PS_CTX_LOCAL_SHA}"
if git -C "${repo_root}" submodule update --remote -- "${PS_CTX_PROMPTS_PATH}" >/dev/null 2>&1; then
  updated_sha="$(git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" rev-parse HEAD 2>/dev/null || true)"
  if [[ -n "${updated_sha}" && "${updated_sha}" == "${PS_CTX_REMOTE_SHA}" ]]; then
    PS_CTX_LOCAL_SHA="${updated_sha}"
    ps_finish_and_exit "pass_auto_updated" "PASS: prompts submodule auto-updated ${previous_sha:0:7} -> ${updated_sha:0:7}" 0
  fi
fi

if ! git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" checkout --detach "${PS_CTX_REMOTE_SHA}" >/dev/null 2>&1; then
  ps_finish_and_exit "fail_checkout" "FAIL: could not checkout ${PS_CTX_REMOTE_SHA:0:7} in ${PS_CTX_PROMPTS_PATH}" 1
fi
PS_CTX_LOCAL_SHA="$(git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" rev-parse HEAD 2>/dev/null || echo unknown)"
ps_finish_and_exit "pass_auto_updated_worktree_only" "PASS: prompts submodule worktree updated ${previous_sha:0:7} -> ${PS_CTX_LOCAL_SHA:0:7} (detached)" 0
