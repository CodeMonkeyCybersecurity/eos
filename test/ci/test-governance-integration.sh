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

tmpdir_direct="$(mktemp -d)"
tmpdir_blocked="$(mktemp -d)"
trap 'rm -rf "${tmpdir_direct}" "${tmpdir_blocked}"' EXIT

mkdir -p "${tmpdir_direct}/scripts/lib" "${tmpdir_direct}/third_party/prompts/scripts"
cp "${GOV_SCRIPT}" "${tmpdir_direct}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir_direct}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir_direct}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir_direct}/scripts/lib/git-env.sh"
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

tmpdir_direct_fail="$(mktemp -d)"
trap 'rm -rf "${tmpdir_direct}" "${tmpdir_blocked}" "${tmpdir_direct_fail}"' EXIT
mkdir -p "${tmpdir_direct_fail}/scripts/lib" "${tmpdir_direct_fail}/third_party/prompts/scripts"
cp "${GOV_SCRIPT}" "${tmpdir_direct_fail}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir_direct_fail}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir_direct_fail}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir_direct_fail}/scripts/lib/git-env.sh"
chmod +x "${tmpdir_direct_fail}/scripts/check-governance.sh"
cat > "${tmpdir_direct_fail}/.gitmodules" <<'EOF_GITMODULES_DIRECT_FAIL'
[submodule "prompts"]
	path = third_party/prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES_DIRECT_FAIL
cat > "${tmpdir_direct_fail}/third_party/prompts/scripts/check-governance.sh" <<'EOF_CHECKER_DIRECT_FAIL'
#!/usr/bin/env bash
exit 7
EOF_CHECKER_DIRECT_FAIL
chmod +x "${tmpdir_direct_fail}/third_party/prompts/scripts/check-governance.sh"

th_assert_run "governance-direct-path-fail" 7 '"outcome":"fail_checker_error"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir_direct_fail}/direct-fail-report.json" bash "${tmpdir_direct_fail}/scripts/check-governance.sh"

mkdir -p "${tmpdir_blocked}/scripts/lib" "${tmpdir_blocked}/prompts/scripts"
cp "${GOV_SCRIPT}" "${tmpdir_blocked}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir_blocked}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir_blocked}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir_blocked}/scripts/lib/git-env.sh"
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

tmpdir_symlink="$(mktemp -d)"
trap 'rm -rf "${tmpdir_direct}" "${tmpdir_blocked}" "${tmpdir_direct_fail}" "${tmpdir_symlink}"' EXIT
mkdir -p "${tmpdir_symlink}/scripts/lib" "${tmpdir_symlink}/prompts/scripts"
cp "${GOV_SCRIPT}" "${tmpdir_symlink}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir_symlink}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir_symlink}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir_symlink}/scripts/lib/git-env.sh"
chmod +x "${tmpdir_symlink}/scripts/check-governance.sh"
cat > "${tmpdir_symlink}/.gitmodules" <<'EOF_GITMODULES_SYMLINK'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES_SYMLINK
cat > "${tmpdir_symlink}/prompts/scripts/check-governance.sh" <<'EOF_CHECKER_SYMLINK'
#!/usr/bin/env bash
exit 0
EOF_CHECKER_SYMLINK
chmod +x "${tmpdir_symlink}/prompts/scripts/check-governance.sh"

th_assert_run "governance-symlink-pass" 0 '"outcome":"pass_checked_via_symlink"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir_symlink}/symlink-report.json" bash "${tmpdir_symlink}/scripts/check-governance.sh"
th_assert_json_field "governance-symlink-outcome" "${tmpdir_symlink}/symlink-report.json" "outcome" "pass_checked_via_symlink"
if [[ -e "${tmpdir_symlink}/third_party/prompts" ]]; then
  echo "FAIL: governance-symlink-cleanup"
  th_fail=$((th_fail + 1))
else
  echo "PASS: governance-symlink-cleanup"
  th_pass=$((th_pass + 1))
fi

tmpdir_symlink_fail="$(mktemp -d)"
trap 'rm -rf "${tmpdir_direct}" "${tmpdir_blocked}" "${tmpdir_direct_fail}" "${tmpdir_symlink}" "${tmpdir_symlink_fail}"' EXIT
mkdir -p "${tmpdir_symlink_fail}/scripts/lib" "${tmpdir_symlink_fail}/prompts/scripts"
cp "${GOV_SCRIPT}" "${tmpdir_symlink_fail}/scripts/check-governance.sh"
cp "${HELPER_SCRIPT}" "${tmpdir_symlink_fail}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir_symlink_fail}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir_symlink_fail}/scripts/lib/git-env.sh"
chmod +x "${tmpdir_symlink_fail}/scripts/check-governance.sh"
cat > "${tmpdir_symlink_fail}/.gitmodules" <<'EOF_GITMODULES_SYMLINK_FAIL'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES_SYMLINK_FAIL
cat > "${tmpdir_symlink_fail}/prompts/scripts/check-governance.sh" <<'EOF_CHECKER_SYMLINK_FAIL'
#!/usr/bin/env bash
exit 9
EOF_CHECKER_SYMLINK_FAIL
chmod +x "${tmpdir_symlink_fail}/prompts/scripts/check-governance.sh"

th_assert_run "governance-symlink-fail" 9 '"outcome":"fail_checker_error"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir_symlink_fail}/symlink-fail-report.json" bash "${tmpdir_symlink_fail}/scripts/check-governance.sh"

th_summary "governance-integration"
