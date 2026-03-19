#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

VERIFY_SCRIPT="${REPO_ROOT}/scripts/ci/verify-parity.sh"

th_assert_run "verify-parity-script-syntax" 0 "" bash -n "${VERIFY_SCRIPT}"
th_assert_run "verify-parity-current-repo" 0 "PASS: ci:debug parity contract verified" bash "${VERIFY_SCRIPT}"
th_assert_run "npm-debug-script-mapping" 0 '"ci:debug"' grep -F '"ci:debug"' "${REPO_ROOT}/package.json"
th_assert_run "pre-commit-uses-npm-ci-debug" 0 "entry: npm run ci:debug --silent" \
  grep -F "entry: npm run ci:debug --silent" "${REPO_ROOT}/.pre-commit-config.yaml"
th_assert_run "npm-self-update-quality-mapping" 0 '"ci:self-update-quality"' grep -F '"ci:self-update-quality"' "${REPO_ROOT}/package.json"

th_summary "verify-parity"
