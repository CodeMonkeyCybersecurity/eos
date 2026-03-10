#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib/prompts-submodule.sh
source "${script_dir}/lib/prompts-submodule.sh"

repo_root="$(ps_repo_root "${BASH_SOURCE[0]}")"
report_path="${GOVERNANCE_REPORT_JSON:-${repo_root}/outputs/ci/governance/report.json}"

created_link=false
created_dir=false
checker_path=""

ps_ctx_init "governance" "${report_path}" "" "${repo_root}" "" "unknown" "unknown" "unknown" "auto" "false"

cleanup() {
  if [[ "${created_link}" == "true" ]]; then
    rm -f "${repo_root}/third_party/prompts"
  fi
  if [[ "${created_dir}" == "true" ]]; then
    rmdir "${repo_root}/third_party" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'ps_finish_and_exit "fail_checker_error" "FAIL: unexpected governance wrapper error at line ${LINENO}" 1' ERR

PS_CTX_PROMPTS_PATH="$(ps_prompts_submodule_path "${repo_root}" || true)"
if [[ -z "${PS_CTX_PROMPTS_PATH}" ]]; then
  ps_finish_and_exit "skip_not_registered" "SKIP: no prompts submodule registered in .gitmodules - governance check not applicable" 0
fi

if [[ -x "${repo_root}/third_party/prompts/scripts/check-governance.sh" ]]; then
  checker_path="${repo_root}/third_party/prompts/scripts/check-governance.sh"
  if CONSUMING_REPO_ROOT="${repo_root}" "${checker_path}"; then
    ps_finish_and_exit "pass_checked_direct" "PASS: governance check completed via third_party/prompts path" 0
  fi
  rc=$?
  ps_finish_and_exit "fail_checker_error" "FAIL: governance checker failed with exit code ${rc}" "${rc}"
fi

if [[ ! -x "${repo_root}/prompts/scripts/check-governance.sh" ]]; then
  ps_finish_and_exit "skip_uninitialized" "SKIP: prompts submodule registered but governance checker not found; run: git submodule update --init --recursive -- ${PS_CTX_PROMPTS_PATH}" 0
fi

if [[ -e "${repo_root}/third_party/prompts" && ! -L "${repo_root}/third_party/prompts" ]]; then
  ps_finish_and_exit "fail_checker_error" "FAIL: cannot create temporary third_party/prompts symlink because the path already exists and is not a symlink" 1
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
  ps_finish_and_exit "pass_checked_via_symlink" "PASS: governance check completed via prompts path with temporary symlink" 0
fi
rc=$?
ps_finish_and_exit "fail_checker_error" "FAIL: governance checker failed with exit code ${rc}" "${rc}"
