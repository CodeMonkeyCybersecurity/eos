#!/usr/bin/env bash
set -Eeuo pipefail

# Default timeout (seconds) for the governance checker subprocess.
PS_GOVERNANCE_CHECKER_TIMEOUT="${PS_GOVERNANCE_CHECKER_TIMEOUT:-120}"

ps_compact_command_error() {
  local detail="${1:-}"
  detail="$(printf '%s' "${detail}" | tr '\n' ' ' | tr -s '[:space:]' ' ')"
  detail="${detail#"${detail%%[![:space:]]*}"}"
  detail="${detail%"${detail##*[![:space:]]}"}"
  if [[ ${#detail} -gt 200 ]]; then
    printf '%.200s...' "${detail}"
  else
    printf '%s' "${detail}"
  fi
}

ps_capture_run() {
  local stdout_file stderr_file rc=0
  stdout_file="$(mktemp)" || return 1
  stderr_file="$(mktemp)" || { rm -f "${stdout_file}"; return 1; }
  # Ensure temp files are cleaned up on any exit path (including signals).
  trap 'rm -f "${stdout_file}" "${stderr_file}"' RETURN
  "$@" >"${stdout_file}" 2>"${stderr_file}" || rc=$?
  PS_LAST_COMMAND_STDOUT="$(cat "${stdout_file}")"
  PS_LAST_COMMAND_STDERR="$(cat "${stderr_file}")"
  return "${rc}"
}

ps_run_freshness() {
  local repo_root="${1:?repo root required}"
  local fetch_timeout_sec="${SUBMODULE_FETCH_TIMEOUT_SEC:-20}"

  ps_ctx_begin \
    "freshness" \
    "freshness" \
    "${SUBMODULE_REPORT_JSON:-${repo_root}/outputs/ci/submodule-freshness/report.json}" \
    "${SUBMODULE_METRICS_TEXTFILE:-}" \
    "${repo_root}" \
    "${STRICT_REMOTE:-auto}" \
    "${AUTO_UPDATE:-false}"
  trap 'ps_finish_and_exit "fail_internal" "FAIL: unexpected script error at line ${LINENO}" 1' ERR

  ps_log_json "INFO" "submodule_freshness.start" "pending" "Starting prompts submodule freshness check"

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
  if ! ps_capture_run ps_git_fetch_remote_branch "${repo_root}/${PS_CTX_PROMPTS_PATH}" "${PS_CTX_REMOTE_BRANCH}" "${fetch_timeout_sec}"; then
    local fetch_error
    fetch_error="$(ps_compact_command_error "${PS_LAST_COMMAND_STDERR:-}")"
    if ps_should_strict_fail_remote "${PS_CTX_STRICT_REMOTE}"; then
      ps_finish_and_exit "fail_remote_unreachable" "FAIL: cannot fetch origin/${PS_CTX_REMOTE_BRANCH} for ${PS_CTX_PROMPTS_PATH} while STRICT_REMOTE=${PS_CTX_STRICT_REMOTE}${fetch_error:+ (${fetch_error})}" 2
    fi
    ps_finish_and_exit "skip_remote_unreachable" "SKIP: cannot fetch origin/${PS_CTX_REMOTE_BRANCH} for ${PS_CTX_PROMPTS_PATH} (offline or auth issue)${fetch_error:+ (${fetch_error})}" 0
  fi

  if ! PS_CTX_REMOTE_SHA="$(git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" rev-parse "origin/${PS_CTX_REMOTE_BRANCH}" 2>/dev/null)"; then
    if ps_should_strict_fail_remote "${PS_CTX_STRICT_REMOTE}"; then
      ps_finish_and_exit "fail_missing_remote_ref" "FAIL: origin/${PS_CTX_REMOTE_BRANCH} not available for ${PS_CTX_PROMPTS_PATH}" 2
    fi
    ps_finish_and_exit "skip_missing_remote_ref" "SKIP: origin/${PS_CTX_REMOTE_BRANCH} not available for ${PS_CTX_PROMPTS_PATH}" 0
  fi

  ps_log_json "INFO" "submodule_freshness.compare" "pending" "Comparing local and remote SHA"

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
  if ps_capture_run git -C "${repo_root}" submodule update --remote -- "${PS_CTX_PROMPTS_PATH}"; then
    updated_sha="$(git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" rev-parse HEAD 2>/dev/null || true)"
    if [[ -n "${updated_sha}" && "${updated_sha}" == "${PS_CTX_REMOTE_SHA}" ]]; then
      PS_CTX_LOCAL_SHA="${updated_sha}"
      ps_finish_and_exit "pass_auto_updated" "PASS: prompts submodule auto-updated ${previous_sha:0:7} -> ${updated_sha:0:7}" 0
    fi
  fi

  if ! ps_capture_run git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" checkout --detach "${PS_CTX_REMOTE_SHA}"; then
    local checkout_error
    checkout_error="$(ps_compact_command_error "${PS_LAST_COMMAND_STDERR:-}")"
    ps_finish_and_exit "fail_checkout" "FAIL: could not checkout ${PS_CTX_REMOTE_SHA:0:7} in ${PS_CTX_PROMPTS_PATH}${checkout_error:+ (${checkout_error})}" 1
  fi
  PS_CTX_LOCAL_SHA="$(git -C "${repo_root}/${PS_CTX_PROMPTS_PATH}" rev-parse HEAD 2>/dev/null || echo unknown)"
  ps_finish_and_exit "pass_auto_updated_worktree_only" "PASS: prompts submodule worktree updated ${previous_sha:0:7} -> ${PS_CTX_LOCAL_SHA:0:7} (detached)" 0
}

ps_run_governance() {
  local repo_root="${1:?repo root required}"
  local checker_path outcome rc=0

  ps_ctx_begin \
    "governance" \
    "governance" \
    "${GOVERNANCE_REPORT_JSON:-${repo_root}/outputs/ci/governance/report.json}" \
    "${GOVERNANCE_METRICS_TEXTFILE:-}" \
    "${repo_root}"
  trap 'ps_finish_and_exit "fail_checker_error" "FAIL: unexpected governance wrapper error at line ${LINENO}" 1' ERR

  ps_log_json "INFO" "governance.start" "pending" "Starting governance check"

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

  # Run the checker with a timeout to prevent hangs from blocking CI.
  local checker_cmd=(bash "${checker_path}")
  if command -v timeout >/dev/null 2>&1; then
    checker_cmd=(timeout --signal=TERM --kill-after=10s "${PS_GOVERNANCE_CHECKER_TIMEOUT}s" "${checker_cmd[@]}")
  fi

  if CONSUMING_REPO_ROOT="${repo_root}" PROMPTS_SUBMODULE_PATH="${PS_CTX_PROMPTS_PATH}" "${checker_cmd[@]}"; then
    ps_finish_and_exit "${outcome}" "PASS: governance check completed via ${PS_CTX_PROMPTS_PATH}" 0
  else
    rc=$?
    if [[ "${rc}" -eq 124 ]]; then
      ps_finish_and_exit "fail_checker_error" "FAIL: governance checker timed out after ${PS_GOVERNANCE_CHECKER_TIMEOUT}s" "${rc}"
    fi
    ps_finish_and_exit "fail_checker_error" "FAIL: governance checker failed with exit code ${rc}" "${rc}"
  fi
}

ps_install_hook() {
  local repo_root="${1:?repo root required}"
  local hook_source="scripts/hooks/pre-commit-ci-debug.sh"
  local hook_dest=".git/hooks/pre-commit"

  ps_ctx_begin \
    "hook_install" \
    "install-hook" \
    "${HOOK_INSTALL_REPORT_JSON:-${repo_root}/outputs/ci/install-hook/report.json}" \
    "${HOOK_INSTALL_METRICS_TEXTFILE:-}" \
    "${repo_root}"
  trap 'ps_finish_and_exit "fail_install" "FAIL: unexpected install-hook error at line ${LINENO}" 1' ERR

  if [[ ! -e "${repo_root}/.git" ]]; then
    ps_finish_and_exit "fail_not_git_repo" "FAIL: not in a git repository" 1
  fi

  mkdir -p "${repo_root}/.git/hooks"
  install -m 0755 "${repo_root}/${hook_source}" "${repo_root}/${hook_dest}"

  local hook_path source_path hook_mode hook_sha source_sha
  hook_path="${repo_root}/${hook_dest}"
  source_path="${repo_root}/${hook_source}"
  hook_mode="$(stat -c '%a' "${hook_path}" 2>/dev/null || stat -f '%OLp' "${hook_path}")"
  hook_sha="$(sha256sum "${hook_path}" 2>/dev/null | awk '{print $1}' || shasum -a 256 "${hook_path}" | awk '{print $1}')"
  source_sha="$(sha256sum "${source_path}" 2>/dev/null | awk '{print $1}' || shasum -a 256 "${source_path}" | awk '{print $1}')"

  # Structured output for both human and machine consumption.
  ps_log_json "INFO" "install_hook.install" "pending" "Installed pre-commit hook at ${hook_path}"
  printf 'Installed pre-commit hook: %s\n' "${hook_path}"
  printf 'Hook source: %s\n' "${source_path}"
  printf 'Hook mode: %s\n' "${hook_mode}"
  printf 'Hook sha256: %s\n' "${hook_sha}"
  printf 'Hook source sha256: %s\n' "${source_sha}"
  if [[ ! -x "${hook_path}" ]]; then
    printf 'Hook executable: false\n'
    ps_finish_and_exit "fail_install" "FAIL: installed hook is not executable" 1
  fi
  printf 'Hook executable: true\n'

  if [[ "${hook_sha}" != "${source_sha}" ]]; then
    printf 'Hook matches source: false\n'
    ps_finish_and_exit "fail_install" "FAIL: installed hook hash does not match source" 1
  fi

  printf 'Hook matches source: true\n'
  printf 'Hook command: bash scripts/prompts-submodule.sh pre-commit\n'
  ps_finish_and_exit "pass_installed" "PASS: installed pre-commit hook" 0
}

ps_run_pre_commit() {
  local repo_root="${1:?repo root required}"
  local staged_files

  # Ensure context lifecycle is active.
  if [[ -z "${PS_CTX_KIND:-}" ]]; then
    ps_ctx_begin \
      "hook" \
      "pre-commit" \
      "${PRE_COMMIT_REPORT_JSON:-${repo_root}/outputs/ci/pre-commit/report.json}" \
      "${PRE_COMMIT_METRICS_TEXTFILE:-}" \
      "${repo_root}"
  fi
  trap 'ps_finish_and_exit "fail_checker_error" "FAIL: unexpected pre-commit error at line ${LINENO}" 1' ERR

  staged_files="$(git -C "${repo_root}" diff --cached --name-only --diff-filter=ACMR)"
  if [[ -z "${staged_files}" ]]; then
    ps_finish_and_exit "pass_no_staged_changes" "PASS: No staged changes" 0
  fi

  ps_log_json "INFO" "pre_commit.parity.start" "pending" "Verifying ci:debug parity contract"
  if [[ -f "${repo_root}/scripts/ci/verify-parity.sh" ]]; then
    bash "${repo_root}/scripts/ci/verify-parity.sh"
  else
    ps_log_json "WARN" "pre_commit.parity.skip" "pending" "verify-parity.sh not found; skipping"
  fi

  ps_log_json "INFO" "pre_commit.ci_debug.start" "pending" "Running ci:debug"
  if [[ -x "${repo_root}/magew" ]]; then
    "${repo_root}/magew" ci:debug
  elif [[ -f "${repo_root}/package.json" ]] && command -v npm >/dev/null 2>&1; then
    ps_log_json "WARN" "pre_commit.ci_debug.fallback" "pending" "magew missing; using npm fallback"
    npm run ci:debug --silent
  else
    ps_log_json "WARN" "pre_commit.ci_debug.fallback" "pending" "magew/npm missing; using script fallback"
    bash "${repo_root}/scripts/ci/debug.sh"
  fi

  if echo "${staged_files}" | grep -Eq '^(pkg/self/|pkg/git/|pkg/vault/phase2_env_setup\.go|cmd/self/|scripts/ci/self-update-quality\.sh|test/e2e/smoke/|package\.json)'; then
    ps_log_json "INFO" "pre_commit.self_update.start" "pending" "Running self-update quality lane"
    if [[ -f "${repo_root}/package.json" ]] && command -v npm >/dev/null 2>&1; then
      npm run ci:self-update-quality --silent
    else
      bash "${repo_root}/scripts/ci/self-update-quality.sh"
    fi
    ps_finish_and_exit "pass_ci_debug_self_update" "PASS: pre-commit checks completed with self-update quality lane" 0
  fi

  ps_finish_and_exit "pass_ci_debug" "PASS: pre-commit checks completed" 0
}
