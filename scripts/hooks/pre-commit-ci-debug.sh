#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${repo_root}"
# shellcheck source=../lib/git-env.sh
source "${repo_root}/scripts/lib/git-env.sh"

staged_files="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "${staged_files}" ]]; then
  echo "pre-commit: no staged changes"
  exit 0
fi

log() {
  local level="${1:?level required}"
  local event="${2:?event required}"
  local message="${3:-}"
  printf '{"ts":"%s","level":"%s","event":"%s","message":"%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${level}" "${event}" "${message}"
}

# Clear hook-exported Git env vars before running ci:debug. This prevents
# cross-repo Git operations in tests from inheriting hook-scoped values.
ge_unset_git_local_env

log "INFO" "pre_commit.parity.start" "verifying ci:debug parity contract"
bash "${repo_root}/scripts/ci/verify-parity.sh"

log "INFO" "pre_commit.ci_debug.start" "running ci:debug via magew"
if [[ -x "${repo_root}/magew" ]]; then
  "${repo_root}/magew" ci:debug
elif [[ -f "${repo_root}/package.json" ]] && command -v npm >/dev/null 2>&1; then
  log "WARN" "pre_commit.ci_debug.fallback" "magew missing; using npm fallback"
  npm run ci:debug --silent
else
  log "WARN" "pre_commit.ci_debug.fallback" "magew/npm missing; using script fallback"
  bash "${repo_root}/scripts/ci/debug.sh"
fi

if echo "${staged_files}" | grep -Eq '^(pkg/self/|pkg/git/|pkg/vault/phase2_env_setup\.go|cmd/self/|scripts/ci/self-update-quality\.sh|test/e2e/smoke/|package\.json)'; then
  log "INFO" "pre_commit.self_update.start" "running self-update quality lane"
  if [[ -f "${repo_root}/package.json" ]] && command -v npm >/dev/null 2>&1; then
    npm run ci:self-update-quality --silent
  else
    bash "${repo_root}/scripts/ci/self-update-quality.sh"
  fi
fi
