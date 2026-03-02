#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

VERIFY_SCRIPT="${REPO_ROOT}/scripts/ci/verify-parity.sh"
MAGEFILE="${REPO_ROOT}/magefile.go"

th_assert_run "verify-parity-script-syntax" 0 "" bash -n "${VERIFY_SCRIPT}"
th_assert_run "verify-parity-current-repo" 0 "PASS: ci:debug parity contract verified" bash "${VERIFY_SCRIPT}"
th_assert_run "mage-debug-wrapper-mapping" 0 "runNpmScript(\"ci:debug\"" rg -F 'runNpmScript("ci:debug"' "${MAGEFILE}"
th_assert_run "mage-self-update-wrapper-mapping" 0 "runNpmScript(\"ci:self-update-quality\"" rg -F 'runNpmScript("ci:self-update-quality"' "${MAGEFILE}"

th_summary "verify-parity"
