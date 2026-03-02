#!/usr/bin/env bash
set -euo pipefail

# verify-parity.sh - Verify ci:debug parity contract
#
# Ensures the same ci:debug entry point is wired across:
#   1. Pre-commit hook (npm run ci:debug -> scripts/ci/debug.sh)
#   2. package.json     ("ci:debug": "bash scripts/ci/debug.sh")
#   3. CI workflow       (npm run ci:debug --silent)
#
# All layers must resolve to scripts/ci/debug.sh as the single source of truth.

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${repo_root}"

hook_file="scripts/hooks/pre-commit-ci-debug.sh"
package_json="package.json"
workflow_candidates=(
  ".gitea/workflows/ci-debug-parity.yml"
  ".github/workflows/ci.yml"
)

assert_file() {
  local file="${1:?file required}"
  if [[ ! -f "${file}" ]]; then
    echo "FAIL: missing file ${file}"
    exit 1
  fi
}

assert_regex() {
  local file="${1:?file required}"
  local pattern="${2:?pattern required}"
  local label="${3:?label required}"

  if ! grep -Eq "${pattern}" "${file}"; then
    echo "FAIL: ${label} missing regex /${pattern}/ in ${file}"
    exit 1
  fi
  echo "PASS: ${label}"
}

# --- Hook file checks ---
assert_file "${hook_file}"
assert_regex "${hook_file}" 'npm run ci:debug' "hook uses npm run ci:debug"
assert_regex "${hook_file}" 'scripts/ci/debug\.sh' "hook fallback uses scripts/ci/debug.sh"

# --- package.json checks ---
assert_file "${package_json}"
assert_regex "${package_json}" '"ci:debug"[[:space:]]*:[[:space:]]*"bash scripts/ci/debug\.sh"' "package.json ci:debug maps to debug script"

# --- Workflow checks ---
found_workflow=0
for workflow_file in "${workflow_candidates[@]}"; do
  if [[ -f "${workflow_file}" ]]; then
    found_workflow=1
    if grep -Eq 'npm run ci:debug' "${workflow_file}"; then
      echo "PASS: workflow ${workflow_file} uses npm run ci:debug"
    else
      echo "FAIL: workflow ${workflow_file} missing ci:debug invocation"
      exit 1
    fi
  fi
done

if [[ "${found_workflow}" -eq 0 ]]; then
  echo "FAIL: no CI workflow file found to verify ci:debug parity"
  exit 1
fi

echo "PASS: ci:debug parity contract verified"
