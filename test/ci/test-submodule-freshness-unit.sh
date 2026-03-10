#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
GIT_ENV_SCRIPT="${REPO_ROOT}/scripts/lib/git-env.sh"
REPORT_ALERT_SCRIPT="${REPO_ROOT}/scripts/ci/report-alert.py"

th_assert_run "freshness-script-syntax" 0 "" bash -n "${FRESHNESS_SCRIPT}"
th_assert_run "helper-script-syntax" 0 "" bash -n "${HELPER_SCRIPT}"
th_assert_run "git-env-script-syntax" 0 "" bash -n "${GIT_ENV_SCRIPT}"
th_assert_run "report-alert-script-syntax" 0 "" python3 -m py_compile "${REPORT_ALERT_SCRIPT}"
th_assert_run "normalize-bool-true-values" 0 "true true true true true false" bash -c '
  source "$1"
  printf "%s %s %s %s %s %s\n" \
    "$(ps_normalize_bool true)" \
    "$(ps_normalize_bool 1)" \
    "$(ps_normalize_bool yes)" \
    "$(ps_normalize_bool y)" \
    "$(ps_normalize_bool on)" \
    "$(ps_normalize_bool no)"
' _ "${HELPER_SCRIPT}"
th_assert_run "normalize-strict-remote-values" 0 "true false auto auto" bash -c '
  source "$1"
  printf "%s %s %s %s\n" \
    "$(ps_normalize_strict_remote true)" \
    "$(ps_normalize_strict_remote false)" \
    "$(ps_normalize_strict_remote auto)" \
    "$(ps_normalize_strict_remote garbage)"
' _ "${HELPER_SCRIPT}"
th_assert_run "ctx-driven-json-log" 0 '"kind":"freshness"' bash -c '
  source "$1"
  ps_ctx_init freshness /tmp/report.json /tmp/metrics.prom /repo prompts deadbeef feedface main auto false
  ps_log_json INFO submodule_freshness.start skip_not_registered "hello"
' _ "${HELPER_SCRIPT}"
th_assert_run "ctx-driven-json-report" 0 "pass" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  ps_ctx_init freshness "${tmpdir}/report.json" "${tmpdir}/metrics.prom" /repo prompts deadbeef feedface main false true
  ps_write_json_report "${tmpdir}/report.json" pass_up_to_date "ok" 0
  python3 - <<PY
import json
from pathlib import Path
report = json.loads(Path(${tmpdir@Q} + "/report.json").read_text(encoding="utf-8"))
assert report["kind"] == "freshness"
assert report["outcome"] == "pass_up_to_date"
assert report["strict_remote"] == "false"
print(report["status"])
PY
' _ "${HELPER_SCRIPT}"
th_assert_run "ctx-driven-metrics" 0 "prompts_submodule_freshness_last_run_timestamp_seconds" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  ps_ctx_init freshness "${tmpdir}/report.json" "${tmpdir}/metrics.prom" /repo prompts deadbeef feedface main auto false
  ps_emit_prom_metrics fail_stale
  cat "${tmpdir}/metrics.prom"
' _ "${HELPER_SCRIPT}"
th_assert_run "git-env-unset-local-vars" 0 "ok" bash -c '
  source "$1"
  export GIT_DIR=/tmp/fake-git
  export GIT_WORK_TREE=/tmp/fake-worktree
  export GIT_INDEX_FILE=/tmp/fake-index
  export GIT_NOT_LOCAL=keep-me
  ge_unset_git_local_env
  ge_unset_git_local_env

  [[ -z "${GIT_DIR:-}" ]] || exit 1
  [[ -z "${GIT_WORK_TREE:-}" ]] || exit 1
  [[ -z "${GIT_INDEX_FILE:-}" ]] || exit 1
  [[ "${GIT_NOT_LOCAL:-}" == "keep-me" ]] || exit 1
  echo ok
' _ "${GIT_ENV_SCRIPT}"

th_assert_run "report-alert-ci-debug-missing" 0 "::warning::ci-debug report missing" \
  python3 "${REPORT_ALERT_SCRIPT}" ci-debug /tmp/does-not-exist-report.json

th_assert_run "artifact-warning-does-not-mask-exit" 0 'artifact_warning' bash -c '
  source "$1"
  (
    ps_ctx_init freshness /proc/eos-test/report.json /proc/eos-test/metrics.prom /repo prompts deadbeef feedface main auto false
    ps_finish_and_exit pass_up_to_date ok 0
  )
' _ "${HELPER_SCRIPT}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
mkdir -p "${tmpdir}/scripts/lib"
cp "${FRESHNESS_SCRIPT}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
cp "${HELPER_SCRIPT}" "${tmpdir}/scripts/lib/prompts-submodule.sh"
chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh"

th_assert_run "skip-no-gitmodules" 0 '"outcome":"skip_not_registered"' \
  env SUBMODULE_REPORT_JSON="${tmpdir}/report1.json" bash "${tmpdir}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-no-gitmodules" "${tmpdir}/report1.json" "outcome" "skip_not_registered"

cat > "${tmpdir}/.gitmodules" <<'EOF_GITMODULES'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES

th_assert_run "skip-uninitialized" 0 '"outcome":"skip_uninitialized"' \
  env SUBMODULE_REPORT_JSON="${tmpdir}/report2.json" bash "${tmpdir}/scripts/prompts-submodule-freshness.sh"
th_assert_json_field "report-outcome-uninitialized" "${tmpdir}/report2.json" "outcome" "skip_uninitialized"
th_assert_json_field "report-status-uninitialized" "${tmpdir}/report2.json" "status" "skip"
th_assert_json_field "report-kind-uninitialized" "${tmpdir}/report2.json" "kind" "freshness"

th_summary "unit"
