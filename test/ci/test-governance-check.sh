#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

GOV_SCRIPT="${REPO_ROOT}/scripts/check-governance.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
REPORT_ALERT_SCRIPT="${REPO_ROOT}/scripts/ci/report-alert.py"

th_assert_run "governance-script-syntax" 0 "" bash -n "${GOV_SCRIPT}"
th_assert_run "helper-script-syntax" 0 "" bash -n "${HELPER_SCRIPT}"
th_assert_run "report-alert-syntax" 0 "" python3 -m py_compile "${REPORT_ALERT_SCRIPT}"

th_assert_run "governance-check-pass" 0 '"event":"governance_check.finish"' \
  env GOVERNANCE_REPORT_JSON="${REPO_ROOT}/outputs/ci/governance/test-report.json" bash "${GOV_SCRIPT}"
th_assert_json_field "governance-report-kind" "${REPO_ROOT}/outputs/ci/governance/test-report.json" "kind" "governance"

if git -C "${REPO_ROOT}" clean -nd | grep -q '^Would remove third_party/$'; then
  echo "FAIL: no-third-party-artifact"
  th_fail=$((th_fail + 1))
else
  echo "PASS: no-third-party-artifact"
  th_pass=$((th_pass + 1))
fi

tmpdir="$(mktemp -d)"
tmpdir_blocked="$(mktemp -d)"

mkdir -p "${tmpdir}/scripts/lib"
cp "${GOV_SCRIPT}" "${tmpdir}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir}/scripts/lib/prompts-submodule.sh"
chmod +x "${tmpdir}/scripts/check-governance.sh"
cat > "${tmpdir}/.gitmodules" <<'EOF_GITMODULES'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES

th_assert_run "governance-skip-uninitialized" 0 '"outcome":"skip_uninitialized"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir}/governance-report.json" bash "${tmpdir}/scripts/check-governance.sh"
th_assert_json_field "governance-skip-kind" "${tmpdir}/governance-report.json" "kind" "governance"

tmpdir_direct="$(mktemp -d)"
trap 'rm -rf "${tmpdir}" "${tmpdir_blocked}" "${tmpdir_direct}"' EXIT
mkdir -p "${tmpdir_direct}/scripts/lib" "${tmpdir_direct}/third_party/prompts/scripts"
cp "${GOV_SCRIPT}" "${tmpdir_direct}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir_direct}/scripts/lib/prompts-submodule.sh"
chmod +x "${tmpdir_direct}/scripts/check-governance.sh"
cat > "${tmpdir_direct}/.gitmodules" <<'EOF_GITMODULES_DIRECT'
[submodule "prompts"]
	path = third_party/prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES_DIRECT
cat > "${tmpdir_direct}/third_party/prompts/scripts/check-governance.sh" <<'EOF_CHECKER_DIRECT'
#!/usr/bin/env bash
exit 0
EOF_CHECKER_DIRECT
chmod +x "${tmpdir_direct}/third_party/prompts/scripts/check-governance.sh"

th_assert_run "governance-direct-path-pass" 0 '"outcome":"pass_checked_direct"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir_direct}/direct-report.json" bash "${tmpdir_direct}/scripts/check-governance.sh"
th_assert_json_field "governance-direct-outcome" "${tmpdir_direct}/direct-report.json" "outcome" "pass_checked_direct"

mkdir -p "${tmpdir_blocked}/scripts/lib" "${tmpdir_blocked}/prompts/scripts"
cp "${GOV_SCRIPT}" "${tmpdir_blocked}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir_blocked}/scripts/lib/prompts-submodule.sh"
chmod +x "${tmpdir_blocked}/scripts/check-governance.sh"
cat > "${tmpdir_blocked}/.gitmodules" <<'EOF_GITMODULES_BLOCKED'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES_BLOCKED
cat > "${tmpdir_blocked}/prompts/scripts/check-governance.sh" <<'EOF_CHECKER'
#!/usr/bin/env bash
exit 0
EOF_CHECKER
chmod +x "${tmpdir_blocked}/prompts/scripts/check-governance.sh"
mkdir -p "${tmpdir_blocked}/third_party/prompts"

th_assert_run "governance-blocked-symlink-path" 1 '"outcome":"fail_checker_error"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir_blocked}/blocked-report.json" bash "${tmpdir_blocked}/scripts/check-governance.sh"
th_assert_json_field "governance-blocked-outcome" "${tmpdir_blocked}/blocked-report.json" "outcome" "fail_checker_error"

th_summary "governance"
