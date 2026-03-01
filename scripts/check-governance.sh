#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/prompts-submodule.sh
source "${script_dir}/lib/prompts-submodule.sh"

repo_root="$(ps_repo_root "${BASH_SOURCE[0]}")"
report_path="${GOVERNANCE_REPORT_JSON:-${repo_root}/outputs/ci/governance/report.json}"

prompts_path=""
created_link=false
created_dir=false
checker_path=""

finish() {
  ps_finish_and_exit "governance" "$1" "$2" "$3" "${report_path}" "" "${repo_root}" "${prompts_path}" "unknown" "unknown" "unknown" "auto" "false"
}

cleanup() {
  if [[ "${created_link}" == "true" ]]; then
    rm -f "${repo_root}/third_party/prompts"
  fi
  if [[ "${created_dir}" == "true" ]]; then
    rmdir "${repo_root}/third_party" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'finish "fail_checker_error" "FAIL: unexpected governance wrapper error at line ${LINENO}" 1' ERR

prompts_path="$(ps_prompts_submodule_path "${repo_root}" || true)"
if [[ -z "${prompts_path}" ]]; then
  finish "skip_not_registered" "SKIP: no prompts submodule registered in .gitmodules — governance check not applicable" 0
fi

if [[ -x "${repo_root}/third_party/prompts/scripts/check-governance.sh" ]]; then
  checker_path="${repo_root}/third_party/prompts/scripts/check-governance.sh"
  if CONSUMING_REPO_ROOT="${repo_root}" "${checker_path}"; then
    finish "pass_checked_direct" "PASS: governance check completed via third_party/prompts path" 0
  fi
  rc=$?
  finish "fail_checker_error" "FAIL: governance checker failed with exit code ${rc}" "${rc}"
fi

if [[ ! -x "${repo_root}/prompts/scripts/check-governance.sh" ]]; then
  finish "skip_uninitialized" "SKIP: prompts submodule registered but governance checker not found; run: git submodule update --init --recursive -- ${prompts_path}" 0
fi

if [[ ! -d "${repo_root}/third_party" ]]; then
  mkdir -p "${repo_root}/third_party"
  created_dir=true
fi
if [[ ! -e "${repo_root}/third_party/prompts" ]]; then
  ln -s ../prompts "${repo_root}/third_party/prompts"
  created_link=true
fi

checker_path="${repo_root}/prompts/scripts/check-governance.sh"
if CONSUMING_REPO_ROOT="${repo_root}" "${checker_path}"; then
  finish "pass_checked_via_symlink" "PASS: governance check completed via prompts path with temporary symlink" 0
fi
rc=$?
finish "fail_checker_error" "FAIL: governance checker failed with exit code ${rc}" "${rc}"
