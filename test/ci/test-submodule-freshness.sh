#!/usr/bin/env bash
# test-submodule-freshness.sh — Unit tests for scripts/prompts-submodule-freshness.sh
#
# Tests the three resilience paths:
#   1. No .gitmodules file → SKIP exit 0
#   2. .gitmodules present but submodule not initialised → SKIP exit 0
#   3. YAML workflow syntax is valid
#
# Usage: bash test/ci/test-submodule-freshness.sh
# Refs: #97, #82, #57

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
WORKFLOW_FILE="${REPO_ROOT}/.gitea/workflows/submodule-freshness.yml"

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

# --- Test 1: Script syntax is valid ---
run_test "script-syntax" 0 "" bash -n "${FRESHNESS_SCRIPT}"

# --- Test 2: No .gitmodules → SKIP exit 0 ---
# Create a temporary directory simulating a repo without .gitmodules
tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

mkdir -p "${tmpdir}/scripts"
cp "${FRESHNESS_SCRIPT}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh"

run_test "no-gitmodules-skip" 0 "SKIP:" bash "${tmpdir}/scripts/prompts-submodule-freshness.sh"

# --- Test 3: .gitmodules present but no submodule dir → SKIP exit 0 ---
cat > "${tmpdir}/.gitmodules" <<'EOF'
[submodule "prompts"]
	path = prompts
	url = http://example.com/prompts.git
EOF

run_test "gitmodules-no-init-skip" 0 "SKIP:" bash "${tmpdir}/scripts/prompts-submodule-freshness.sh"

# --- Test 4: Workflow YAML is valid ---
run_test "workflow-yaml-syntax" 0 "" python3 -c "
import yaml
with open('${WORKFLOW_FILE}') as f:
    yaml.safe_load(f)
"

# --- Test 5: Workflow does NOT use submodules: recursive ---
if grep -q 'submodules: recursive' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "FAIL: workflow-no-recursive — workflow still uses 'submodules: recursive'"
  fail=$((fail + 1))
else
  echo "PASS: workflow-no-recursive — checkout does not use submodules: recursive"
  pass=$((pass + 1))
fi

# --- Test 6: .gitmodules uses HTTPS URL (not SSH) ---
if grep -q 'ssh://' "${REPO_ROOT}/.gitmodules" 2>/dev/null; then
  echo "FAIL: gitmodules-https — .gitmodules still uses SSH URL"
  fail=$((fail + 1))
else
  echo "PASS: gitmodules-https — .gitmodules uses HTTPS URL"
  pass=$((pass + 1))
fi

# --- Test 7: Workflow has separate submodule init step ---
if grep -q 'Init submodules' "${WORKFLOW_FILE}" 2>/dev/null; then
  echo "PASS: workflow-manual-init — workflow has manual submodule init step"
  pass=$((pass + 1))
else
  echo "FAIL: workflow-manual-init — workflow missing manual submodule init step"
  fail=$((fail + 1))
fi

# --- Summary ---
echo ""
echo "Results: ${pass} passed, ${fail} failed, $((pass + fail)) total"

if [[ "${fail}" -gt 0 ]]; then
  exit 1
fi
exit 0
