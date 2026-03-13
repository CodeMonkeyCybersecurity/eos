#!/usr/bin/env bash
set -Eeuo pipefail

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
    true)  return 0 ;;
    false) return 1 ;;
    *)     ci_in_ci; return $? ;;
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

# ps_submodule_is_diverged returns 0 (true) when the submodule's local checkout
# has commits that are NOT on the remote branch (i.e., ahead_count > 0).
# This distinguishes a "diverged" state from a merely "stale" one:
#   - stale: local is behind remote, simple --remote fast-forward works
#   - diverged: local has extra commits, needs rebase before --remote update
# The function expects that 'git fetch origin <branch>' has already been called.
ps_submodule_is_diverged() {
  local repo_root="${1:?repo root required}"
  local submodule_path="${2:?submodule path required}"
  local remote_branch="${3:?remote branch required}"
  local ahead_count
  ahead_count="$(git -C "${repo_root}/${submodule_path}" \
    rev-list --count "origin/${remote_branch}..HEAD" 2>/dev/null || echo "0")"
  [[ "${ahead_count}" -gt 0 ]]
}

# ps_configure_submodule_pull_strategy sets pull.rebase = true in the
# submodule's local git config so that 'git pull' never requires interactive
# reconciliation. Without this, Git >= 2.27 fails with:
#   fatal: Need to specify how to reconcile divergent branches.
# This must be called once per submodule checkout (e.g., after init).
ps_configure_submodule_pull_strategy() {
  local repo_path="${1:?repo path required}"
  git -C "${repo_path}" config pull.rebase true 2>/dev/null || true
}

ps_governance_checker_path() {
  local repo_root="${1:?repo root required}"
  local prompts_path="${2:?prompts path required}"
  local checker_path="${repo_root}/${prompts_path}/scripts/check-governance.sh"
  if [[ -x "${checker_path}" ]]; then
    printf '%s\n' "${checker_path}"
    return 0
  fi
  return 1
}

