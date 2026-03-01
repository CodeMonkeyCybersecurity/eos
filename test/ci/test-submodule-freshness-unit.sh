#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"

th_assert_run "freshness-script-syntax" 0 "" bash -n "${FRESHNESS_SCRIPT}"
th_assert_run "helper-script-syntax" 0 "" bash -n "${HELPER_SCRIPT}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
mkdir -p "${tmpdir}/scripts/lib"
cp "${FRESHNESS_SCRIPT}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
cp "${HELPER_SCRIPT}" "${tmpdir}/scripts/lib/prompts-submodule.sh"
chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh"

th_assert_run "skip-no-gitmodules" 0 '"outcome":"skip_not_registered"' \
  env SUBMODULE_REPORT_JSON="${tmpdir}/report1.json" bash "${tmpdir}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-no-gitmodules" "${tmpdir}/report1.json" "outcome" "skip_not_registered"

cat > "${tmpdir}/.gitmodules" <<'EOF'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF

th_assert_run "skip-uninitialized" 0 '"outcome":"skip_uninitialized"' \
  env SUBMODULE_REPORT_JSON="${tmpdir}/report2.json" bash "${tmpdir}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-uninitialized" "${tmpdir}/report2.json" "outcome" "skip_uninitialized"

th_summary "unit"
