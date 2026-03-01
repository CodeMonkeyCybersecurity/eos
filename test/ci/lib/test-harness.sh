#!/usr/bin/env bash
set -euo pipefail

th_pass=0
th_fail=0

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
    return 1
  fi

  if [[ -n "${expected_output}" ]] && ! grep -qF "${expected_output}" <<< "${output}"; then
    echo "FAIL: ${name} - expected output containing '${expected_output}'"
    echo "  output: ${output}"
    th_fail=$((th_fail + 1))
    return 1
  fi

  echo "PASS: ${name}"
  th_pass=$((th_pass + 1))
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
  return 1
}

th_summary() {
  local suite="${1:-suite}"
  echo ""
  echo "[${suite}] Results: ${th_pass} passed, ${th_fail} failed, $((th_pass + th_fail)) total"
  [[ "${th_fail}" -eq 0 ]]
}

