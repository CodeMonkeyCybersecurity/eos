#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

WORKFLOW_FILE="${REPO_ROOT}/.gitea/workflows/submodule-freshness.yml"
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

# Verify SUBMODULE_INIT is written to the env file (GITEA_ENV/GITHUB_ENV) and
# not just echoed to stdout.  The naive 'echo VAR=val' pattern does NOT persist
# across steps in Gitea or GitHub Actions.
if grep -qE '\$\{GITEA_ENV:-\$\{GITHUB_ENV:-' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "PASS: workflow-submodule-init-uses-env-file"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: workflow-submodule-init-uses-env-file (SUBMODULE_INIT must be written to GITEA_ENV/GITHUB_ENV, not stdout)"
  th_fail=$((th_fail + 1))
fi

# Verify pull.rebase is configured after submodule init to prevent
# 'fatal: Need to specify how to reconcile divergent branches' on Git >= 2.27.
if grep -q 'pull.rebase true' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "PASS: workflow-configures-pull-rebase"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: workflow-configures-pull-rebase (git config pull.rebase true must be set after submodule init)"
  th_fail=$((th_fail + 1))
fi

# --- Smoke test with fixture ---
tmpdir="$(th_create_fixture)"
trap 'rm -rf "${tmpdir}"' EXIT

th_assert_run "repo-script-smoke" 0 '"outcome":"skip_not_registered"' \
  env STRICT_REMOTE=false AUTO_UPDATE=false SUBMODULE_REPORT_JSON="${tmpdir}/e2e-report.json" SUBMODULE_METRICS_TEXTFILE="${tmpdir}/e2e-metrics.prom" bash "${tmpdir}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "repo-script-smoke-report-kind" "${tmpdir}/e2e-report.json" "kind" "freshness"
th_assert_json_field "repo-script-smoke-schema" "${tmpdir}/e2e-report.json" "schema_version" "2"

if [[ -f "${tmpdir}/e2e-metrics.prom" ]]; then
  echo "PASS: metrics-file-emitted"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: metrics-file-emitted"
  th_fail=$((th_fail + 1))
fi

th_assert_run "report-alert-skip" 0 '::warning::submodule freshness skipped' \
  python3 "${REPORT_ALERT_SCRIPT}" submodule-freshness "${tmpdir}/e2e-report.json"

th_summary "e2e"
