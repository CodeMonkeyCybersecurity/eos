#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

# --- Direct path (third_party/prompts) ---
tmpdir_direct="$(th_create_fixture)"
trap 'rm -rf "${tmpdir_direct}"' EXIT

mkdir -p "${tmpdir_direct}/third_party/prompts/scripts"
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

# --- Direct path checker failure ---
tmpdir_direct_fail="$(th_create_fixture)"
trap 'rm -rf "${tmpdir_direct}" "${tmpdir_direct_fail}"' EXIT

mkdir -p "${tmpdir_direct_fail}/third_party/prompts/scripts"
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

# --- Override path (prompts/) ---
tmpdir_override="$(th_create_fixture)"
trap 'rm -rf "${tmpdir_direct}" "${tmpdir_direct_fail}" "${tmpdir_override}"' EXIT

mkdir -p "${tmpdir_override}/prompts/scripts" "${tmpdir_override}/prompts/lib"
cat > "${tmpdir_override}/.gitmodules" <<'EOF_GITMODULES_OVERRIDE'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES_OVERRIDE
cat > "${tmpdir_override}/prompts/scripts/check-governance.sh" <<'EOF_CHECKER_OVERRIDE'
#!/usr/bin/env bash
echo "OK: ${PROMPTS_SUBMODULE_PATH}/ submodule present"
echo "OK: README.md references ${PROMPTS_SUBMODULE_PATH}/"
echo
echo "PASS: Governance wiring is complete"
EOF_CHECKER_OVERRIDE
chmod +x "${tmpdir_override}/prompts/scripts/check-governance.sh"
printf 'dummy\n' > "${tmpdir_override}/prompts/SOAPIER.md"
printf '%s\n' "# repo" "third_party/prompts/" > "${tmpdir_override}/README.md"

th_assert_run "governance-override-path-pass" 0 '"outcome":"pass_checked_via_override"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir_override}/override-report.json" bash "${tmpdir_override}/scripts/check-governance.sh"
th_assert_json_field "governance-override-outcome" "${tmpdir_override}/override-report.json" "outcome" "pass_checked_via_override"
th_assert_json_field "governance-override-prompts-path" "${tmpdir_override}/override-report.json" "prompts_path" "prompts"

th_summary "governance-integration"
