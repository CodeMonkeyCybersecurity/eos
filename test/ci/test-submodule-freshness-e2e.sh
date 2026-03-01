#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

WORKFLOW_FILE="${REPO_ROOT}/.gitea/workflows/submodule-freshness.yml"
FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"

th_assert_run "workflow-yaml-valid" 0 "" python3 -c "
import yaml
with open(${WORKFLOW_FILE@Q}, 'r', encoding='utf-8') as f:
    yaml.safe_load(f)
"

if grep -q 'submodules: recursive' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "FAIL: workflow-no-recursive-checkout"
  th_fail=$((th_fail + 1))
else
  echo "PASS: workflow-no-recursive-checkout"
  th_pass=$((th_pass + 1))
fi

if grep -q 'Init submodules (HTTPS with token)' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "PASS: workflow-manual-init-step"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: workflow-manual-init-step"
  th_fail=$((th_fail + 1))
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
mkdir -p "${tmpdir}/scripts/lib"
cp "${FRESHNESS_SCRIPT}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
cp "${HELPER_SCRIPT}" "${tmpdir}/scripts/lib/prompts-submodule.sh"
chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh"

th_assert_run "repo-script-smoke" 0 '"outcome":"skip_not_registered"' \
  env STRICT_REMOTE=false AUTO_UPDATE=false SUBMODULE_REPORT_JSON="${tmpdir}/e2e-report.json" SUBMODULE_METRICS_TEXTFILE="${tmpdir}/e2e-metrics.prom" bash "${tmpdir}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "repo-script-smoke-report-kind" "${tmpdir}/e2e-report.json" "kind" "freshness"

if [[ -f "${tmpdir}/e2e-metrics.prom" ]]; then
  echo "PASS: metrics-file-emitted"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: metrics-file-emitted"
  th_fail=$((th_fail + 1))
fi

th_summary "e2e"
