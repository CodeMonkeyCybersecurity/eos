#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

GOV_SCRIPT="${REPO_ROOT}/scripts/check-governance.sh"
ENTRY_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule.sh"
INSTALL_HOOK_SCRIPT="${REPO_ROOT}/scripts/install-git-hooks.sh"
PRE_COMMIT_SCRIPT="${REPO_ROOT}/scripts/hooks/pre-commit-ci-debug.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
CI_COMMON_SCRIPT="${REPO_ROOT}/scripts/lib/ci-common.sh"
GIT_ENV_SCRIPT="${REPO_ROOT}/scripts/lib/git-env.sh"
REPORT_ALERT_SCRIPT="${REPO_ROOT}/scripts/ci/report-alert.py"

th_assert_run "governance-script-syntax" 0 "" bash -n "${GOV_SCRIPT}"
th_assert_run "entry-script-syntax" 0 "" bash -n "${ENTRY_SCRIPT}"
th_assert_run "install-hook-script-syntax" 0 "" bash -n "${INSTALL_HOOK_SCRIPT}"
th_assert_run "pre-commit-script-syntax" 0 "" bash -n "${PRE_COMMIT_SCRIPT}"
th_assert_run "helper-script-syntax" 0 "" bash -n "${HELPER_SCRIPT}"
th_assert_run "ci-common-script-syntax" 0 "" bash -n "${CI_COMMON_SCRIPT}"
th_assert_run "git-env-script-syntax" 0 "" bash -n "${GIT_ENV_SCRIPT}"
th_assert_run "report-alert-syntax" 0 "" python3 -m py_compile "${REPORT_ALERT_SCRIPT}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
mkdir -p "${tmpdir}/scripts/lib"
cp "${GOV_SCRIPT}" "${tmpdir}/scripts/check-governance.sh"
cp "${ENTRY_SCRIPT}" "${tmpdir}/scripts/prompts-submodule.sh"
cp "${HELPER_SCRIPT}" "${tmpdir}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir}/scripts/lib/git-env.sh"
mkdir -p "${tmpdir}/scripts/lib/prompts-submodule"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/common.sh" "${tmpdir}/scripts/lib/prompts-submodule/common.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/context.sh" "${tmpdir}/scripts/lib/prompts-submodule/context.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/git.sh" "${tmpdir}/scripts/lib/prompts-submodule/git.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/artifacts.sh" "${tmpdir}/scripts/lib/prompts-submodule/artifacts.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/actions.sh" "${tmpdir}/scripts/lib/prompts-submodule/actions.sh"
chmod +x "${tmpdir}/scripts/check-governance.sh" "${tmpdir}/scripts/prompts-submodule.sh"
cat > "${tmpdir}/.gitmodules" <<'EOF_GITMODULES'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES

th_assert_run "governance-skip-uninitialized" 0 '"outcome":"skip_uninitialized"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir}/governance-report.json" bash "${tmpdir}/scripts/check-governance.sh"
th_assert_json_field "governance-skip-kind" "${tmpdir}/governance-report.json" "kind" "governance"
th_assert_json_field "governance-skip-action" "${tmpdir}/governance-report.json" "action" "governance"
th_assert_json_field "governance-skip-schema" "${tmpdir}/governance-report.json" "schema_version" "2"

hook_tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}" "${hook_tmpdir}"' EXIT
mkdir -p "${hook_tmpdir}/scripts/lib" "${hook_tmpdir}/scripts/hooks"
git -C "${hook_tmpdir}" init -q
cp "${ENTRY_SCRIPT}" "${hook_tmpdir}/scripts/prompts-submodule.sh"
cp "${INSTALL_HOOK_SCRIPT}" "${hook_tmpdir}/scripts/install-git-hooks.sh"
cp "${PRE_COMMIT_SCRIPT}" "${hook_tmpdir}/scripts/hooks/pre-commit-ci-debug.sh"
cp "${HELPER_SCRIPT}" "${hook_tmpdir}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${hook_tmpdir}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${hook_tmpdir}/scripts/lib/git-env.sh"
mkdir -p "${hook_tmpdir}/scripts/lib/prompts-submodule"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/common.sh" "${hook_tmpdir}/scripts/lib/prompts-submodule/common.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/context.sh" "${hook_tmpdir}/scripts/lib/prompts-submodule/context.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/git.sh" "${hook_tmpdir}/scripts/lib/prompts-submodule/git.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/artifacts.sh" "${hook_tmpdir}/scripts/lib/prompts-submodule/artifacts.sh"
cp "${REPO_ROOT}/scripts/lib/prompts-submodule/actions.sh" "${hook_tmpdir}/scripts/lib/prompts-submodule/actions.sh"
chmod +x "${hook_tmpdir}/scripts/prompts-submodule.sh" "${hook_tmpdir}/scripts/install-git-hooks.sh" "${hook_tmpdir}/scripts/hooks/pre-commit-ci-debug.sh"

th_assert_run "install-hook-installs-wrapper" 0 "Hook matches source: true" \
  bash -c 'cd "$1" && bash scripts/install-git-hooks.sh' _ "${hook_tmpdir}"

th_assert_run "pre-commit-no-staged-changes" 0 "pre-commit: no staged changes" \
  bash -c 'cd "$1" && bash scripts/hooks/pre-commit-ci-debug.sh' _ "${hook_tmpdir}"

th_summary "governance-unit"
