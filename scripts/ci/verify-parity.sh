#!/usr/bin/env bash
set -euo pipefail

# verify-parity.sh - Verify ci:debug parity contract
#
# Ensures the same ci:debug entry point is wired across:
#   1. Git hook wrapper         -> scripts/prompts-submodule.sh pre-commit
#   2. pre-commit framework     -> npm run ci:debug --silent
#   3. package.json             -> bash scripts/ci/debug.sh
#   4. magew target             -> npm run ci:debug --silent (legacy compatibility)
#   5. CI workflow              -> npm run ci:debug --silent
#   6. Make target              -> magew ci:debug (legacy compatibility)
#
# Pre-commit and governance wrappers must delegate through scripts/prompts-submodule.sh,
# while ci:debug itself remains rooted at scripts/ci/debug.sh.

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "${repo_root}"

hook_file="scripts/hooks/pre-commit-ci-debug.sh"
pre_commit_config=".pre-commit-config.yaml"
entry_file="scripts/prompts-submodule.sh"
entry_actions_file="scripts/lib/prompts-submodule/actions.sh"
magew_file="magew"
makefile="Makefile"
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
assert_regex "${hook_file}" 'scripts/prompts-submodule\.sh" pre-commit' "hook delegates to prompts-submodule entry point"

# --- pre-commit framework checks ---
assert_file "${pre_commit_config}"
assert_regex "${pre_commit_config}" 'id:[[:space:]]*ci-debug-parity' "pre-commit config exposes ci-debug parity hook"
assert_regex "${pre_commit_config}" 'entry:[[:space:]]*npm run ci:debug --silent' "pre-commit config uses npm ci:debug entry point"

# --- prompts-submodule entry point checks ---
assert_file "${entry_file}"
assert_regex "${entry_file}" 'freshness\|governance\|install-hook\|pre-commit' "entry point exposes expected subcommands"
assert_file "${entry_actions_file}"
assert_regex "${entry_actions_file}" 'npm run ci:debug --silent' "entry point supports npm ci:debug fallback"
assert_regex "${entry_actions_file}" 'scripts/ci/debug\.sh' "entry point fallback uses scripts/ci/debug.sh"

# --- package.json checks ---
assert_file "${package_json}"
assert_regex "${package_json}" '"ci:debug"[[:space:]]*:[[:space:]]*"bash scripts/ci/debug\.sh"' "package.json ci:debug maps to debug script"

# --- magew checks ---
assert_file "${magew_file}"
assert_regex "${magew_file}" 'ci:debug\|launch:verify' "magew exposes ci:debug target"
assert_regex "${magew_file}" 'npm run ci:debug --silent' "magew dispatches ci:debug to npm"
assert_regex "${magew_file}" 'scripts/ci/debug\.sh' "magew has script fallback for ci:debug"

# --- Makefile checks ---
assert_file "${makefile}"
assert_regex "${makefile}" '^ci-debug:.*' "make ci-debug target exists"
assert_regex "${makefile}" '\./magew ci:debug' "make ci-debug dispatches to magew"

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
