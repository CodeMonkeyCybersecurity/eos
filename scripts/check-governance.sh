#!/usr/bin/env bash
set -euo pipefail

# Run prompts governance checks regardless of submodule path convention.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -x "${repo_root}/third_party/prompts/scripts/check-governance.sh" ]]; then
  CONSUMING_REPO_ROOT="${repo_root}" "${repo_root}/third_party/prompts/scripts/check-governance.sh"
  exit $?
fi

if [[ ! -x "${repo_root}/prompts/scripts/check-governance.sh" ]]; then
  echo "ERROR: prompts governance checker not found in third_party/prompts/ or prompts/"
  exit 2
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
}
trap cleanup EXIT

CONSUMING_REPO_ROOT="${repo_root}" "${repo_root}/prompts/scripts/check-governance.sh"
