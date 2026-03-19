#!/usr/bin/env bash
# Integration tests for prompts/scripts/propagate.sh.
# Runs the script with --dry-run against the real eos repo structure.
# Tests step-filtering, output streams, and flag combinations.
# 20% tier — uses real repo filesystem, safe because --dry-run modifies nothing.
#
# GUARD: The dispatcher (test-propagate.sh) checks for submodule presence
# before calling this file. If you run this file directly, ensure
# prompts/scripts/propagate.sh exists.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"
# shellcheck source=../../scripts/lib/git-env.sh
source "${REPO_ROOT}/scripts/lib/git-env.sh"

export GIT_ALLOW_PROTOCOL="file:https:http:ssh"

PROPAGATE_SCRIPT="${REPO_ROOT}/prompts/scripts/propagate.sh"

# --- dry-run exits 0 against real repo ---
th_assert_run "dry-run-exits-0" 0 "" \
  bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}"

# --- dry-run stdout contains summary ---
th_assert_run "dry-run-stdout-has-summary" 0 "=== Propagation Summary ===" \
  bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}"

# --- dry-run stdout shows all 5 steps ---
for step in submodule skills mcp settings stage; do
  th_assert_run "dry-run-summary-includes-${step}" 0 "${step}" \
    bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}"
done

# --- dry-run message confirms no files modified ---
th_assert_run "dry-run-no-files-modified-message" 0 "No files were modified" \
  bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}"

# --- stderr is structured, stdout is the summary ---
# Confirm nothing from the structured log leaks onto stdout
_stdout_only=""
_stdout_only="$(bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" 2>/dev/null)"
th_assert_not_contains "structured-log-must-not-appear-on-stdout" "${_stdout_only}" "[propagate] ts="

# Confirm structured log IS on stderr
_stderr_only=""
_stderr_only="$(bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" 2>&1 >/dev/null)"
th_assert_contains "structured-log-on-stderr" "${_stderr_only}" "[propagate]"

# --- --only filtering: single step ---
# --only submodule should produce a summary with submodule step and skip others
_only_out=""
_only_out="$(bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" --only submodule 2>/dev/null)"
th_assert_run "only-submodule-exits-0" 0 "" \
  bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" --only submodule

# submodule step should appear in summary
th_assert_contains "only-submodule-step-in-summary" "${_only_out}" "submodule"

# Non-selected steps remain visible as SKIP in the human summary.
th_assert_contains "only-submodule-marks-skills-skip" "${_only_out}" "skills       SKIP"

# --- --skip filtering ---
th_assert_run "skip-skills-exits-0" 0 "" \
  bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" --skip skills

# When skills is skipped, summary should still show other steps
_skip_out=""
_skip_out="$(bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" --skip skills 2>/dev/null)"
for step in submodule mcp settings stage; do
  th_assert_contains "skip-skills-shows-${step}" "${_skip_out}" "${step}"
done

# --- Multiple --only flags ---
th_assert_run "only-multiple-steps-exits-0" 0 "" \
  bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" \
    --only submodule --only skills

# --- --repo-root flag wired correctly ---
# Passing a non-existent repo root must fail with non-zero exit
_badroot_exit=0
bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "/tmp/no-such-repo-root-$$" >/dev/null 2>&1 || _badroot_exit=$?
if [[ "${_badroot_exit}" -ne 0 ]]; then
  echo "PASS: invalid-repo-root-fails"
  th_pass=$((th_pass + 1))
else
  echo "FAIL: invalid-repo-root-fails (expected non-zero, got 0)"
  th_fail=$((th_fail + 1))
fi

# --- Verbose flag accepted ---
th_assert_run "verbose-flag-accepted" 0 "" \
  bash "${PROPAGATE_SCRIPT}" --dry-run --repo-root "${REPO_ROOT}" -v

th_summary "integration"
