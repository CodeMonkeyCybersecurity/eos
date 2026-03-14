#!/usr/bin/env bash
# Unit tests for scripts/submodule-bootstrap.sh
# Tests: syntax, argument parsing, function isolation (no git operations)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

BOOTSTRAP_SCRIPT="${REPO_ROOT}/scripts/submodule-bootstrap.sh"

# --- Syntax checks ---
th_assert_run "bootstrap-script-syntax" 0 "" bash -n "${BOOTSTRAP_SCRIPT}"

# --- Help flag ---
th_assert_run "bootstrap-help-flag" 0 "Usage:" bash "${BOOTSTRAP_SCRIPT}" --help

# --- Unknown argument ---
th_assert_run "bootstrap-unknown-arg" 2 "Unknown argument" bash "${BOOTSTRAP_SCRIPT}" --bogus

# --- Mutually exclusive flags work without error ---
# --status should succeed in this repo (we have .gitmodules)
th_assert_run "bootstrap-status-flag" 0 "Submodule Status" bash "${BOOTSTRAP_SCRIPT}" --status

# --- check_gitmodules function ---
th_assert_run "bootstrap-gitmodules-exists" 0 "" bash -c '
  source /dev/stdin <<'"'"'SCRIPT'"'"'
check_gitmodules() {
  local gitmodules="${REPO_ROOT}/.gitmodules"
  if [[ ! -f "${gitmodules}" ]]; then
    return 1
  fi
  if ! grep -q "\[submodule \"prompts\"\]" "${gitmodules}"; then
    return 1
  fi
  return 0
}
SCRIPT
REPO_ROOT='"${REPO_ROOT}"'
check_gitmodules
'

# --- check_url_matches function ---
th_assert_run "bootstrap-url-matches-expected" 0 "" bash -c '
  cd "'"${REPO_ROOT}"'"
  url="$(git config --file .gitmodules submodule.prompts.url 2>/dev/null)"
  if [[ "${url}" == "https://gitea.cybermonkey.sh/cybermonkey/prompts.git" ]]; then
    exit 0
  else
    echo "URL mismatch: ${url}"
    exit 1
  fi
'

# --- is_initialized function ---
th_assert_run "bootstrap-is-initialized" 0 "" bash -c '
  submodule_dir="'"${REPO_ROOT}"'/prompts"
  [[ -d "${submodule_dir}/.git" ]] || [[ -f "${submodule_dir}/.git" ]]
'

# --- check_symlink function ---
th_assert_run "bootstrap-symlink-correct" 0 "" bash -c '
  symlink="'"${REPO_ROOT}"'/third_party/prompts"
  if [[ -L "${symlink}" ]]; then
    target="$(readlink "${symlink}")"
    if [[ "${target}" == "../prompts" ]]; then
      exit 0
    else
      echo "Symlink target: ${target}"
      exit 1
    fi
  else
    echo "Not a symlink"
    exit 1
  fi
'

# --- Script is executable ---
th_assert_run "bootstrap-is-executable" 0 "" test -x "${BOOTSTRAP_SCRIPT}"

# --- Exit codes documented in header ---
th_assert_run "bootstrap-documents-exit-codes" 0 "Exit codes:" grep "Exit codes:" "${BOOTSTRAP_SCRIPT}"

th_summary "submodule-bootstrap-unit"
