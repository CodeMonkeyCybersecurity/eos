#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
auto_update="${AUTO_UPDATE:-false}"

prompts_path=""
if [[ -d "${repo_root}/prompts/.git" || -f "${repo_root}/prompts/.git" ]]; then
  prompts_path="prompts"
elif [[ -d "${repo_root}/third_party/prompts/.git" || -f "${repo_root}/third_party/prompts/.git" ]]; then
  prompts_path="third_party/prompts"
fi

if [[ -z "${prompts_path}" ]]; then
  echo "FAIL: prompts submodule not found at prompts/ or third_party/prompts/"
  exit 1
fi

local_sha="$(git -C "${repo_root}/${prompts_path}" rev-parse HEAD)"
if ! git -C "${repo_root}/${prompts_path}" fetch origin main --quiet; then
  echo "FAIL: unable to fetch ${prompts_path} origin/main"
  exit 1
fi
remote_sha="$(git -C "${repo_root}/${prompts_path}" rev-parse origin/main)"

echo "prompts_path=${prompts_path}"
echo "local_sha=${local_sha}"
echo "remote_sha=${remote_sha}"

if [[ "${local_sha}" == "${remote_sha}" ]]; then
  echo "PASS: prompts submodule is up to date"
  exit 0
fi

echo "WARN: prompts submodule is stale"
if [[ "${auto_update}" == "true" ]]; then
  if git -C "${repo_root}" submodule status -- "${prompts_path}" >/dev/null 2>&1; then
    git -C "${repo_root}" submodule update --remote -- "${prompts_path}"
    updated_sha="$(git -C "${repo_root}/${prompts_path}" rev-parse HEAD)"
    echo "UPDATED_SUBMODULE: ${local_sha:0:7} -> ${updated_sha:0:7}"
    exit 0
  fi

  git -C "${repo_root}/${prompts_path}" checkout --detach "${remote_sha}" >/dev/null 2>&1
  updated_sha="$(git -C "${repo_root}/${prompts_path}" rev-parse HEAD)"
  echo "UPDATED_WORKTREE_ONLY: ${local_sha:0:7} -> ${updated_sha:0:7}"
  exit 0
fi

echo "Run: git submodule update --remote -- ${prompts_path}"
exit 1
