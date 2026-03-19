#!/usr/bin/env bash
set -euo pipefail

th_pass=0
th_fail=0

# th_assert_run runs a command and checks exit code + optional output pattern.
# IMPORTANT: Always returns 0 so set -e callers accumulate all results.
# Failures are tracked via th_fail counter; th_summary exits non-zero if any failed.
th_assert_run() {
  local name="${1:?name required}"
  local expected_exit="${2:?expected exit required}"
  local expected_output="${3:-}"
  shift 3

  local output=""
  local exit_code=0
  output="$("$@" 2>&1)" || exit_code=$?

  if [[ "${exit_code}" -ne "${expected_exit}" ]]; then
    echo "FAIL: ${name} - expected exit ${expected_exit}, got ${exit_code}"
    echo "  output: ${output}"
    th_fail=$((th_fail + 1))
    return 0
  fi

  if [[ -n "${expected_output}" ]] && ! grep -qF "${expected_output}" <<< "${output}"; then
    echo "FAIL: ${name} - expected output containing '${expected_output}'"
    echo "  output: ${output}"
    th_fail=$((th_fail + 1))
    return 0
  fi

  echo "PASS: ${name}"
  th_pass=$((th_pass + 1))
  return 0
}

th_assert_contains() {
  local name="${1:?name required}"
  local haystack="${2:-}"
  local needle="${3:?needle required}"

  if grep -qF "${needle}" <<< "${haystack}"; then
    echo "PASS: ${name}"
    th_pass=$((th_pass + 1))
    return 0
  fi

  echo "FAIL: ${name} - expected output containing '${needle}'"
  echo "  output: ${haystack}"
  th_fail=$((th_fail + 1))
  return 0
}

th_assert_not_contains() {
  local name="${1:?name required}"
  local haystack="${2:-}"
  local needle="${3:?needle required}"

  if grep -qF "${needle}" <<< "${haystack}"; then
    echo "FAIL: ${name} - did not expect output containing '${needle}'"
    echo "  output: ${haystack}"
    th_fail=$((th_fail + 1))
    return 0
  fi

  echo "PASS: ${name}"
  th_pass=$((th_pass + 1))
  return 0
}

th_assert_file_exists() {
  local name="${1:?name required}"
  local path="${2:?path required}"

  if [[ -e "${path}" ]]; then
    echo "PASS: ${name}"
    th_pass=$((th_pass + 1))
    return 0
  fi

  echo "FAIL: ${name} - expected file to exist at ${path}"
  th_fail=$((th_fail + 1))
  return 0
}

th_assert_exit_code() {
  local name="${1:?name required}"
  local got="${2:?exit code required}"
  local want="${3:?expected exit required}"

  if [[ "${got}" -eq "${want}" ]]; then
    echo "PASS: ${name}"
    th_pass=$((th_pass + 1))
    return 0
  fi

  echo "FAIL: ${name} - expected exit ${want}, got ${got}"
  th_fail=$((th_fail + 1))
  return 0
}

th_assert_nonzero_exit() {
  local name="${1:?name required}"
  local got="${2:?exit code required}"

  if [[ "${got}" -ne 0 ]]; then
    echo "PASS: ${name}"
    th_pass=$((th_pass + 1))
    return 0
  fi

  echo "FAIL: ${name} - expected non-zero exit, got 0"
  th_fail=$((th_fail + 1))
  return 0
}

th_assert_json_field() {
  local name="${1:?name required}"
  local path="${2:?path required}"
  local field="${3:?field required}"
  local want="${4:?want required}"

  if python3 - <<PY
import json
with open(${path@Q}, "r", encoding="utf-8") as f:
    data = json.load(f)
if str(data.get(${field@Q}, "")) != ${want@Q}:
    raise SystemExit(f"expected {${field@Q}}={${want@Q}}, got {data.get(${field@Q})!r}")
PY
  then
    echo "PASS: ${name}"
    th_pass=$((th_pass + 1))
    return 0
  fi

  echo "FAIL: ${name}"
  th_fail=$((th_fail + 1))
  return 0
}

th_summary() {
  local suite="${1:-suite}"
  echo ""
  echo "[${suite}] Results: ${th_pass} passed, ${th_fail} failed, $((th_pass + th_fail)) total"
  [[ "${th_fail}" -eq 0 ]]
}

# th_create_fixture copies the prompts-submodule library tree into a temp dir.
# Returns the fixture root path via stdout. Caller is responsible for cleanup.
# Usage: fixture_dir="$(th_create_fixture)"
th_create_fixture() {
  local repo_root
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
  local dest
  dest="$(mktemp -d)"

  mkdir -p "${dest}/scripts/lib/prompts-submodule" "${dest}/scripts/hooks" "${dest}/scripts/ci"

  # Entry points and wrappers
  cp "${repo_root}/scripts/prompts-submodule.sh"         "${dest}/scripts/prompts-submodule.sh"
  cp "${repo_root}/scripts/check-governance.sh"          "${dest}/scripts/check-governance.sh"
  cp "${repo_root}/scripts/prompts-submodule-freshness.sh" "${dest}/scripts/prompts-submodule-freshness.sh"
  cp "${repo_root}/scripts/install-git-hooks.sh"         "${dest}/scripts/install-git-hooks.sh"
  cp "${repo_root}/scripts/hooks/pre-commit-ci-debug.sh" "${dest}/scripts/hooks/pre-commit-ci-debug.sh"

  # Library modules
  cp "${repo_root}/scripts/lib/ci-common.sh"             "${dest}/scripts/lib/ci-common.sh"
  cp "${repo_root}/scripts/lib/git-env.sh"               "${dest}/scripts/lib/git-env.sh"
  cp "${repo_root}/scripts/lib/prompts-submodule.sh"     "${dest}/scripts/lib/prompts-submodule.sh"
  for f in common.sh context.sh git.sh artifacts.sh actions.sh; do
    cp "${repo_root}/scripts/lib/prompts-submodule/${f}" "${dest}/scripts/lib/prompts-submodule/${f}"
  done

  # Optional CI scripts (copy if they exist)
  if [[ -f "${repo_root}/scripts/ci/report-alert.py" ]]; then
    cp "${repo_root}/scripts/ci/report-alert.py" "${dest}/scripts/ci/report-alert.py"
    chmod +x "${dest}/scripts/ci/report-alert.py"
  fi

  # Set executable bits
  chmod +x "${dest}/scripts/prompts-submodule.sh" \
           "${dest}/scripts/check-governance.sh" \
           "${dest}/scripts/prompts-submodule-freshness.sh" \
           "${dest}/scripts/install-git-hooks.sh" \
           "${dest}/scripts/hooks/pre-commit-ci-debug.sh"

  printf '%s\n' "${dest}"
}
