#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

GOV_SCRIPT="${REPO_ROOT}/scripts/check-governance.sh"
WORKFLOW_FILE="${REPO_ROOT}/.gitea/workflows/governance-check.yml"

# Ensure pyyaml is available — catthehacker/ubuntu:act-latest does not pre-install it.
# pip install is idempotent; --break-system-packages required on Ubuntu 23+ externally-managed envs.
if ! python3 -c "import yaml" 2>/dev/null; then
  python3 -m pip install --quiet pyyaml --break-system-packages 2>/dev/null \
    || python3 -m pip install --quiet pyyaml 2>/dev/null \
    || true
fi

th_assert_run "governance-workflow-yaml-valid" 0 "" python3 -c "
import yaml
with open(${WORKFLOW_FILE@Q}, 'r', encoding='utf-8') as f:
    yaml.safe_load(f)
"

if grep -q 'Init submodules (HTTPS with token)' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "PASS: governance-workflow-manual-init-step"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: governance-workflow-manual-init-step"
  th_fail=$((th_fail + 1))
fi

if grep -q 'python3 scripts/ci/report-alert.py governance' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "PASS: governance-workflow-alert-helper"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: governance-workflow-alert-helper"
  th_fail=$((th_fail + 1))
fi

th_assert_run "governance-check-pass" 0 '"event":"governance_check.finish"' \
  env GOVERNANCE_REPORT_JSON="${REPO_ROOT}/outputs/ci/governance/test-report.json" bash "${GOV_SCRIPT}"
th_assert_json_field "governance-report-kind" "${REPO_ROOT}/outputs/ci/governance/test-report.json" "kind" "governance"
th_assert_json_field "governance-report-schema" "${REPO_ROOT}/outputs/ci/governance/test-report.json" "schema_version" "2"
th_assert_json_field "governance-report-events-path" "${REPO_ROOT}/outputs/ci/governance/test-report.json" "events_path" "${REPO_ROOT}/outputs/ci/governance/events.jsonl"

th_summary "governance-e2e"
