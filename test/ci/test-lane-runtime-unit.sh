#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

LANE_RUNTIME="${REPO_ROOT}/scripts/ci/lib/lane-runtime.sh"

# --- Syntax ---
th_assert_run "lane-runtime-syntax" 0 "" bash -n "${LANE_RUNTIME}"

# --- lane_init creates output directory and events file ---
th_assert_run "lane-init-creates-dir" 0 "ok" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  [[ -d "${tmpdir}/outputs/ci/test-lane" ]] || exit 1
  [[ -f "${tmpdir}/outputs/ci/test-lane/events.jsonl" ]] || exit 1
  [[ "${CI_LANE_STEP_SEQ}" -eq 0 ]] || exit 1
  [[ "${CI_LANE_STAGE}" == "bootstrap" ]] || exit 1
  echo ok
' _ "${LANE_RUNTIME}"

# --- lane_log produces valid JSON with ci_json_obj ---
th_assert_run "lane-log-valid-json" 0 "test-lane" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  output="$(lane_log INFO test.event "hello world" bootstrap)"
  echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[\"lane\"]==\"test-lane\"; assert d[\"exit_code\"]==0; print(d[\"lane\"])"
' _ "${LANE_RUNTIME}"

# --- lane_log handles special characters safely ---
th_assert_run "lane-log-special-chars" 0 "ok" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  output="$(lane_log INFO test.event "msg with \"quotes\" and newlines" bootstrap 1 42 "cmd with spaces")"
  echo "${output}" | python3 -c "import sys,json; json.load(sys.stdin); print(\"ok\")"
' _ "${LANE_RUNTIME}"

# --- lane_run_step increments sequence counter ---
th_assert_run "lane-step-sequence" 0 "#2" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  lane_run_step "step_a" true
  output="$(lane_run_step "step_b" true)"
  echo "${output}" | grep -o "#2"
' _ "${LANE_RUNTIME}"

# --- lane_finish produces valid report JSON ---
th_assert_run "lane-finish-report-json" 0 "pass" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  (lane_finish "pass" "all good" 0) >/dev/null 2>&1 || true
  python3 -c "
import json
r = json.load(open(\"${tmpdir}/outputs/ci/test-lane/report.json\"))
assert r[\"status\"] == \"pass\"
assert r[\"steps_executed\"] == 0
assert r[\"exit_code\"] == 0
print(r[\"status\"])
"
' _ "${LANE_RUNTIME}"

# --- lane_finish with extra report fields ---
th_assert_run "lane-finish-extra-fields" 0 "42" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  CI_LANE_EXTRA_REPORT_FIELDS="coverage=#int:42
name=test-value"
  (lane_finish "pass" "with extras" 0) >/dev/null 2>&1 || true
  python3 -c "
import json
r = json.load(open(\"${tmpdir}/outputs/ci/test-lane/report.json\"))
assert r[\"coverage\"] == 42, f\"expected 42 got {r.get(\"coverage\")}\"
assert r[\"name\"] == \"test-value\"
print(r[\"coverage\"])
"
' _ "${LANE_RUNTIME}"

# --- lane_emit_base_metrics writes prometheus format ---
th_assert_run "lane-metrics-format" 0 "ci_lane_status" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  lane_emit_base_metrics "pass" 10
  cat "${tmpdir}/outputs/ci/test-lane/metrics.prom"
' _ "${LANE_RUNTIME}"

# --- lane_emit_base_metrics appends extra metrics ---
th_assert_run "lane-extra-metrics" 0 "custom_metric" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  CI_LANE_EXTRA_METRICS="# TYPE custom_metric gauge
custom_metric 99"
  lane_emit_base_metrics "pass" 10
  cat "${tmpdir}/outputs/ci/test-lane/metrics.prom"
' _ "${LANE_RUNTIME}"

# --- lane_on_err captures failure context ---
th_assert_run "lane-on-err-captures-context" 0 "fail" bash "${SCRIPT_DIR}/helpers/test-lane-on-err.sh" "${LANE_RUNTIME}"

# --- lane_acquire_lock prevents concurrent runs ---
th_assert_run "lane-lock-prevents-concurrent" 0 "already running" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  lane_acquire_lock
  # Second instance should fail
  (
    source "$1"
    lane_init "test-lane" "${tmpdir}"
    lane_acquire_lock 2>&1
  ) 2>&1 || true
' _ "${LANE_RUNTIME}"

# --- _lane_release_lock is idempotent ---
th_assert_run "lane-release-lock-idempotent" 0 "ok" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  lane_init "test-lane" "${tmpdir}"
  lane_acquire_lock
  _lane_release_lock
  _lane_release_lock  # second call should not error
  echo ok
' _ "${LANE_RUNTIME}"

th_summary "lane-runtime-unit"
