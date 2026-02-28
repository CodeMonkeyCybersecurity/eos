#!/usr/bin/env bash
# test-governance-check.sh — Regression tests for scripts/check-governance.sh
#
# Validates local wrapper behavior:
#   1. Script syntax is valid
#   2. Running governance-check does not leave untracked third_party/ artifact
#
# Usage: bash test/ci/test-governance-check.sh
# Refs: #115

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GOV_SCRIPT="${REPO_ROOT}/scripts/check-governance.sh"

pass=0
fail=0

run_test() {
  local name="$1"
  local expected_exit="$2"
  local expected_output="$3"
  shift 3

  local actual_output
  local actual_exit=0
  actual_output=$("$@" 2>&1) || actual_exit=$?

  if [[ "${actual_exit}" -ne "${expected_exit}" ]]; then
    echo "FAIL: ${name} — expected exit ${expected_exit}, got ${actual_exit}"
    echo "  Output: ${actual_output}"
    fail=$((fail + 1))
    return
  fi

  if [[ -n "${expected_output}" ]] && ! echo "${actual_output}" | grep -qF "${expected_output}"; then
    echo "FAIL: ${name} — expected output containing '${expected_output}'"
    echo "  Got: ${actual_output}"
    fail=$((fail + 1))
    return
  fi

  echo "PASS: ${name}"
  pass=$((pass + 1))
}

run_test "script-syntax" 0 "" bash -n "${GOV_SCRIPT}"
run_test "governance-check-pass" 0 "PASS: Governance wiring is complete" bash "${GOV_SCRIPT}"

if git -C "${REPO_ROOT}" clean -nd | grep -q '^Would remove third_party/$'; then
  echo "FAIL: no-third-party-artifact — governance-check left untracked third_party/"
  fail=$((fail + 1))
else
  echo "PASS: no-third-party-artifact"
  pass=$((pass + 1))
fi

echo ""
echo "Results: ${pass} passed, ${fail} failed, $((pass + fail)) total"

if [[ "${fail}" -gt 0 ]]; then
  exit 1
fi
exit 0
