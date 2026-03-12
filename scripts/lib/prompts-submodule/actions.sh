#!/usr/bin/env bash
set -Eeuo pipefail

ps_run_freshness() {
  local repo_root="${1:?repo root required}"
  local fetch_timeout_sec="${SUBMODULE_FETCH_TIMEOUT_SEC:-20}"

  PS_CTX_KIND="freshness"
  PS_CTX_ACTION="freshness"
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

  local previous_sha updated_sha
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
}

ps_run_governance() {
  local repo_root="${1:?repo root required}"
  local checker_path outcome rc=0

  PS_CTX_KIND="governance"
  PS_CTX_ACTION="governance"
  PS_CTX_REPORT_PATH="${GOVERNANCE_REPORT_JSON:-${repo_root}/outputs/ci/governance/report.json}"
  PS_CTX_REPO_ROOT="${repo_root}"
  ps_ctx_init
  trap 'ps_finish_and_exit "fail_checker_error" "FAIL: unexpected governance wrapper error at line ${LINENO}" 1' ERR

  PS_CTX_PROMPTS_PATH="$(ps_prompts_submodule_path "${repo_root}" || true)"
  if [[ -z "${PS_CTX_PROMPTS_PATH}" ]]; then
    ps_finish_and_exit "skip_not_registered" "SKIP: no prompts submodule registered in .gitmodules - governance check not applicable" 0
  fi

  checker_path="$(ps_governance_checker_path "${repo_root}" "${PS_CTX_PROMPTS_PATH}" || true)"
  if [[ -z "${checker_path}" ]]; then
    ps_finish_and_exit "skip_uninitialized" "SKIP: prompts submodule registered but governance checker not found; run: git submodule update --init --recursive -- ${PS_CTX_PROMPTS_PATH}" 0
  fi

  if [[ "${PS_CTX_PROMPTS_PATH}" == "third_party/prompts" ]]; then
    outcome="pass_checked_direct"
  else
    outcome="pass_checked_via_override"
  fi

  if CONSUMING_REPO_ROOT="${repo_root}" PROMPTS_SUBMODULE_PATH="${PS_CTX_PROMPTS_PATH}" "${checker_path}"; then
    ps_finish_and_exit "${outcome}" "PASS: governance check completed via ${PS_CTX_PROMPTS_PATH}" 0
  else
    rc=$?
    ps_finish_and_exit "fail_checker_error" "FAIL: governance checker failed with exit code ${rc}" "${rc}"
  fi
}

ps_install_hook() {
  local repo_root="${1:?repo root required}"
  local hook_source="scripts/hooks/pre-commit-ci-debug.sh"
  local hook_dest=".git/hooks/pre-commit"

  if [[ ! -e "${repo_root}/.git" ]]; then
    echo "Error: not in a git repository"
    return 1
  fi

  mkdir -p "${repo_root}/.git/hooks"
  install -m 0755 "${repo_root}/${hook_source}" "${repo_root}/${hook_dest}"

  local hook_path source_path hook_mode hook_sha source_sha
  hook_path="${repo_root}/${hook_dest}"
  source_path="${repo_root}/${hook_source}"
  hook_mode="$(stat -c '%a' "${hook_path}" 2>/dev/null || stat -f '%OLp' "${hook_path}")"
  hook_sha="$(sha256sum "${hook_path}" 2>/dev/null | awk '{print $1}' || shasum -a 256 "${hook_path}" | awk '{print $1}')"
  source_sha="$(sha256sum "${source_path}" 2>/dev/null | awk '{print $1}' || shasum -a 256 "${source_path}" | awk '{print $1}')"

  echo "Installed pre-commit hook: ${hook_path}"
  echo "Hook source: ${source_path}"
  echo "Hook mode: ${hook_mode}"
  echo "Hook sha256: ${hook_sha}"
  echo "Hook source sha256: ${source_sha}"
  if [[ ! -x "${hook_path}" ]]; then
    echo "Hook executable: false"
    return 1
  fi
  echo "Hook executable: true"

  if [[ "${hook_sha}" != "${source_sha}" ]]; then
    echo "Hook matches source: false"
    return 1
  fi

  echo "Hook matches source: true"
  echo "Hook command: bash scripts/prompts-submodule.sh pre-commit"
}

ps_run_pre_commit() {
  local repo_root="${1:?repo root required}"
  local staged_files

  staged_files="$(git -C "${repo_root}" diff --cached --name-only --diff-filter=ACMR)"
  if [[ -z "${staged_files}" ]]; then
    echo "pre-commit: no staged changes"
    return 0
  fi

  ps_log_json "INFO" "pre_commit.parity.start" "pass_checked_direct" "verifying ci:debug parity contract"
  bash "${repo_root}/scripts/ci/verify-parity.sh"

  ps_log_json "INFO" "pre_commit.ci_debug.start" "pass_checked_direct" "running ci:debug via magew"
  if [[ -x "${repo_root}/magew" ]]; then
    "${repo_root}/magew" ci:debug
  elif [[ -f "${repo_root}/package.json" ]] && command -v npm >/dev/null 2>&1; then
    ps_log_json "WARN" "pre_commit.ci_debug.fallback" "skip_missing_remote_ref" "magew missing; using npm fallback"
    npm run ci:debug --silent
  else
    ps_log_json "WARN" "pre_commit.ci_debug.fallback" "skip_missing_remote_ref" "magew/npm missing; using script fallback"
    bash "${repo_root}/scripts/ci/debug.sh"
  fi

  if echo "${staged_files}" | grep -Eq '^(pkg/self/|pkg/git/|pkg/vault/phase2_env_setup\.go|cmd/self/|scripts/ci/self-update-quality\.sh|test/e2e/smoke/|package\.json)'; then
    ps_log_json "INFO" "pre_commit.self_update.start" "pass_checked_direct" "running self-update quality lane"
    if [[ -f "${repo_root}/package.json" ]] && command -v npm >/dev/null 2>&1; then
      npm run ci:self-update-quality --silent
    else
      bash "${repo_root}/scripts/ci/self-update-quality.sh"
    fi
  fi
}
