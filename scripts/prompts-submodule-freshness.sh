#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/prompts-submodule.sh
source "${script_dir}/lib/prompts-submodule.sh"

repo_root="$(ps_repo_root "${BASH_SOURCE[0]}")"
auto_update="$(ps_normalize_bool "${AUTO_UPDATE:-false}")"
strict_remote="$(printf '%s' "${STRICT_REMOTE:-auto}" | tr '[:upper:]' '[:lower:]')"
report_path="${SUBMODULE_REPORT_JSON:-${repo_root}/outputs/ci/submodule-freshness/report.json}"
metrics_path="${SUBMODULE_METRICS_TEXTFILE:-}"

local_sha="unknown"
remote_sha="unknown"
remote_branch="unknown"
prompts_path=""

finish() {
  local outcome="${1:?outcome required}"
  local message="${2:?message required}"
  local exit_code="${3:?exit code required}"

  if ! ps_outcome_known "freshness" "${outcome}"; then
    outcome="fail_corrupt_submodule"
    message="FAIL: internal error - unknown outcome emitted"
    exit_code=1
  fi

  ps_log_json "INFO" "submodule_freshness.finish" "${outcome}" "${message}" "${repo_root}" "${prompts_path}" "${local_sha}" "${remote_sha}" "${remote_branch}" "${strict_remote}" "${auto_update}"
  ps_write_json_report "${report_path}" "freshness" "${outcome}" "${message}" "${repo_root}" "${prompts_path}" "${local_sha}" "${remote_sha}" "${remote_branch}" "${strict_remote}" "${auto_update}" "${exit_code}"
  ps_emit_prom_metrics "${metrics_path}" "${outcome}" "${strict_remote}"
  exit "${exit_code}"
}

ps_log_json "INFO" "submodule_freshness.start" "skip_not_registered" "Starting prompts submodule freshness check" "${repo_root}" "${prompts_path}" "${local_sha}" "${remote_sha}" "${remote_branch}" "${strict_remote}" "${auto_update}"

prompts_path="$(ps_prompts_submodule_path "${repo_root}" || true)"
if [[ -z "${prompts_path}" ]]; then
  finish "skip_not_registered" "SKIP: no prompts submodule registered in .gitmodules — nothing to check" 0
fi

if ! ps_prompts_submodule_initialized "${repo_root}" "${prompts_path}"; then
  finish "skip_uninitialized" "SKIP: prompts submodule exists but is not initialized. Run: git submodule update --init --recursive -- ${prompts_path}" 0
fi

if ! local_sha="$(git -C "${repo_root}/${prompts_path}" rev-parse HEAD 2>/dev/null)"; then
  finish "fail_corrupt_submodule" "FAIL: cannot read HEAD for ${prompts_path}; submodule may be corrupt. Run: git submodule update --init --force -- ${prompts_path}" 1
fi

remote_branch="$(ps_tracking_branch "${repo_root}" "${prompts_path}")"
if ! git -C "${repo_root}/${prompts_path}" fetch origin "${remote_branch}" --quiet --no-tags 2>/dev/null; then
  if ps_should_strict_fail_remote "${strict_remote}"; then
    finish "fail_remote_unreachable" "FAIL: cannot fetch origin/${remote_branch} for ${prompts_path} while STRICT_REMOTE=${strict_remote}" 2
  fi
  finish "skip_remote_unreachable" "SKIP: cannot fetch origin/${remote_branch} for ${prompts_path} (offline or auth issue)" 0
fi

if ! remote_sha="$(git -C "${repo_root}/${prompts_path}" rev-parse "origin/${remote_branch}" 2>/dev/null)"; then
  if ps_should_strict_fail_remote "${strict_remote}"; then
    finish "fail_missing_remote_ref" "FAIL: origin/${remote_branch} not available for ${prompts_path}" 2
  fi
  finish "skip_missing_remote_ref" "SKIP: origin/${remote_branch} not available for ${prompts_path}" 0
fi

ps_log_json "INFO" "submodule_freshness.compare" "pass_up_to_date" "Comparing local and remote SHA" "${repo_root}" "${prompts_path}" "${local_sha}" "${remote_sha}" "${remote_branch}" "${strict_remote}" "${auto_update}"

if [[ "${local_sha}" == "${remote_sha}" ]]; then
  finish "pass_up_to_date" "PASS: prompts submodule is up to date" 0
fi

if [[ "${auto_update}" != "true" ]]; then
  finish "fail_stale" "FAIL: prompts submodule is stale (${local_sha:0:7} != ${remote_sha:0:7}). Run: git submodule update --remote -- ${prompts_path}" 1
fi

previous_sha="${local_sha}"
if git -C "${repo_root}" submodule update --remote -- "${prompts_path}" >/dev/null 2>&1; then
  updated_sha="$(git -C "${repo_root}/${prompts_path}" rev-parse HEAD 2>/dev/null || true)"
  if [[ -n "${updated_sha}" && "${updated_sha}" == "${remote_sha}" ]]; then
    local_sha="${updated_sha}"
    finish "pass_auto_updated" "PASS: prompts submodule auto-updated ${previous_sha:0:7} -> ${updated_sha:0:7}" 0
  fi
fi

if ! git -C "${repo_root}/${prompts_path}" checkout --detach "${remote_sha}" >/dev/null 2>&1; then
  finish "fail_checkout" "FAIL: could not checkout ${remote_sha:0:7} in ${prompts_path}" 1
fi
local_sha="$(git -C "${repo_root}/${prompts_path}" rev-parse HEAD 2>/dev/null || echo unknown)"
finish "pass_auto_updated_worktree_only" "PASS: prompts submodule worktree updated ${previous_sha:0:7} -> ${local_sha:0:7} (detached)" 0
