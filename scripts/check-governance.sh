#!/usr/bin/env bash
set -euo pipefail

# Run prompts governance checks regardless of submodule path convention.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Pre-check: if .gitmodules does not exist or does not reference prompts,
# the submodule is not registered in this repo yet — skip gracefully.
if [[ ! -f "${repo_root}/.gitmodules" ]] || ! grep -q '\[submodule.*prompts' "${repo_root}/.gitmodules" 2>/dev/null; then
  echo "SKIP: no prompts submodule registered in .gitmodules — governance check not applicable"
  exit 0
fi

if [[ -x "${repo_root}/third_party/prompts/scripts/check-governance.sh" ]]; then
  CONSUMING_REPO_ROOT="${repo_root}" "${repo_root}/third_party/prompts/scripts/check-governance.sh"
  exit $?
fi

if [[ ! -x "${repo_root}/prompts/scripts/check-governance.sh" ]]; then
  echo "WARN: prompts submodule registered but governance checker not found"
  echo "  Expected at: third_party/prompts/scripts/check-governance.sh"
  echo "  Or at: prompts/scripts/check-governance.sh"
  echo "  Run: git submodule update --init --recursive"
  echo "SKIP: cannot run governance check without initialised submodule"
  exit 0
fi

mkdir -p "${repo_root}/third_party"
created_link=false
if [[ ! -e "${repo_root}/third_party/prompts" ]]; then
  ln -s ../prompts "${repo_root}/third_party/prompts"
  created_link=true
fi

cleanup() {
  if [[ "${created_link}" == "true" ]]; then
    rm -f "${repo_root}/third_party/prompts"
  fi
  # Remove helper directory only if it is empty.
  rmdir "${repo_root}/third_party" 2>/dev/null || true
}
trap cleanup EXIT

CONSUMING_REPO_ROOT="${repo_root}" "${repo_root}/prompts/scripts/check-governance.sh"
