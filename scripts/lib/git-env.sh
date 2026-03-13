#!/usr/bin/env bash

# ge_unset_git_local_env removes Git-local environment variables that hooks export.
# This is required before running git commands against foreign repositories.
ge_unset_git_local_env() {
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

  if ! command -v git >/dev/null 2>&1; then
    return 0
  fi

  local git_var=""
  while IFS= read -r git_var; do
    if [[ -n "${git_var}" ]]; then
      unset "${git_var}" || true
    fi
  done < <(git rev-parse --local-env-vars 2>/dev/null || true)
}

# ge_run_clean_git executes a command with Git-local env vars cleared.
ge_run_clean_git() {
  (
    ge_unset_git_local_env
    "$@"
  )
}