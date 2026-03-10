#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

GOV_SCRIPT="${REPO_ROOT}/scripts/check-governance.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
CI_COMMON_SCRIPT="${REPO_ROOT}/scripts/lib/ci-common.sh"
GIT_ENV_SCRIPT="${REPO_ROOT}/scripts/lib/git-env.sh"
REPORT_ALERT_SCRIPT="${REPO_ROOT}/scripts/ci/report-alert.py"

th_assert_run "governance-script-syntax" 0 "" bash -n "${GOV_SCRIPT}"
th_assert_run "helper-script-syntax" 0 "" bash -n "${HELPER_SCRIPT}"
th_assert_run "ci-common-script-syntax" 0 "" bash -n "${CI_COMMON_SCRIPT}"
th_assert_run "git-env-script-syntax" 0 "" bash -n "${GIT_ENV_SCRIPT}"
th_assert_run "report-alert-syntax" 0 "" python3 -m py_compile "${REPORT_ALERT_SCRIPT}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
mkdir -p "${tmpdir}/scripts/lib"
cp "${GOV_SCRIPT}" "${tmpdir}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir}/scripts/lib/git-env.sh"
chmod +x "${tmpdir}/scripts/check-governance.sh"
cat > "${tmpdir}/.gitmodules" <<'EOF_GITMODULES'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES

th_assert_run "governance-skip-uninitialized" 0 '"outcome":"skip_uninitialized"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir}/governance-report.json" bash "${tmpdir}/scripts/check-governance.sh"
th_assert_json_field "governance-skip-kind" "${tmpdir}/governance-report.json" "kind" "governance"

th_summary "governance-unit"
