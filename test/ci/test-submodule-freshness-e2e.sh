#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

WORKFLOW_FILE="${REPO_ROOT}/.gitea/workflows/submodule-freshness.yml"
FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
CI_COMMON_SCRIPT="${REPO_ROOT}/scripts/lib/ci-common.sh"
GIT_ENV_SCRIPT="${REPO_ROOT}/scripts/lib/git-env.sh"
REPORT_ALERT_SCRIPT="${REPO_ROOT}/scripts/ci/report-alert.py"

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

if grep -q 'python3 scripts/ci/report-alert.py submodule-freshness' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "PASS: workflow-alert-helper"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: workflow-alert-helper"
  th_fail=$((th_fail + 1))
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
mkdir -p "${tmpdir}/scripts/lib" "${tmpdir}/scripts/ci"
cp "${FRESHNESS_SCRIPT}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
cp "${HELPER_SCRIPT}" "${tmpdir}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir}/scripts/lib/git-env.sh"
cp "${REPORT_ALERT_SCRIPT}" "${tmpdir}/scripts/ci/report-alert.py"
chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh" "${tmpdir}/scripts/ci/report-alert.py"

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

th_assert_run "report-alert-skip" 0 '::warning::submodule freshness skipped' \
  python3 "${tmpdir}/scripts/ci/report-alert.py" submodule-freshness "${tmpdir}/e2e-report.json"

th_summary "e2e"
