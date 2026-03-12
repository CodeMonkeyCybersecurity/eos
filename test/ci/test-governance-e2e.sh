#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

GOV_SCRIPT="${REPO_ROOT}/scripts/check-governance.sh"

th_assert_run "governance-check-pass" 0 '"event":"governance_check.finish"' \
  env GOVERNANCE_REPORT_JSON="${REPO_ROOT}/outputs/ci/governance/test-report.json" bash "${GOV_SCRIPT}"
th_assert_json_field "governance-report-kind" "${REPO_ROOT}/outputs/ci/governance/test-report.json" "kind" "governance"
th_assert_json_field "governance-report-schema" "${REPO_ROOT}/outputs/ci/governance/test-report.json" "schema_version" "2"

th_summary "governance-e2e"
