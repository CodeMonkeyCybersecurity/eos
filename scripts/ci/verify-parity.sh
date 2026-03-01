#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${repo_root}"

hook_file="scripts/hooks/pre-commit-ci-debug.sh"
magefile_file="magefile.go"
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

assert_file "${hook_file}"
assert_file "${magefile_file}"

assert_regex "${hook_file}" '"\$\{repo_root\}/magew"[[:space:]]+ci:debug' "hook uses magew ci:debug"
assert_regex "${hook_file}" '(^|[[:space:]])mage[[:space:]]+ci:debug($|[[:space:]])' "hook fallback uses mage ci:debug"
assert_regex "${magefile_file}" 'run\("bash",[[:space:]]*"scripts/ci/debug\.sh"\)' "mage target maps to debug script"

found_workflow=0
for workflow_file in "${workflow_candidates[@]}"; do
  if [[ -f "${workflow_file}" ]]; then
    found_workflow=1
    assert_regex "${workflow_file}" '\./magew[[:space:]]+ci:debug' "workflow ${workflow_file} runs mage ci:debug"
  fi
done

if [[ "${found_workflow}" -eq 0 ]]; then
  echo "FAIL: no CI workflow file found to verify ci:debug parity"
  exit 1
fi

echo "PASS: ci:debug parity contract verified"
