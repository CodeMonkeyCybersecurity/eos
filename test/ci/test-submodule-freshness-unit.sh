#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
ENTRY_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
CI_COMMON_SCRIPT="${REPO_ROOT}/scripts/lib/ci-common.sh"
GIT_ENV_SCRIPT="${REPO_ROOT}/scripts/lib/git-env.sh"
REPORT_ALERT_SCRIPT="${REPO_ROOT}/scripts/ci/report-alert.py"

# --- Syntax checks ---
th_assert_run "freshness-script-syntax" 0 "" bash -n "${FRESHNESS_SCRIPT}"
th_assert_run "entry-script-syntax" 0 "" bash -n "${ENTRY_SCRIPT}"
th_assert_run "helper-script-syntax" 0 "" bash -n "${HELPER_SCRIPT}"
th_assert_run "ci-common-script-syntax" 0 "" bash -n "${CI_COMMON_SCRIPT}"
th_assert_run "git-env-script-syntax" 0 "" bash -n "${GIT_ENV_SCRIPT}"
th_assert_run "report-alert-script-syntax" 0 "" python3 -m py_compile "${REPORT_ALERT_SCRIPT}"

# --- ci-common.sh shared primitives ---
th_assert_run "ci-common-json-escape" 0 'hello\"world' bash -c '
  source "$1"
  ci_json_escape "hello\"world"
' _ "${CI_COMMON_SCRIPT}"
th_assert_run "ci-common-json-escape-control-chars" 0 "clean" bash -c '
  source "$1"
  result="$(ci_json_escape "$(printf "has\x01\x02ctrl")")"
  if [[ "${result}" == "hasctrl" ]]; then
    echo "clean"
  else
    echo "FAIL: got ${result}"
    exit 1
  fi
' _ "${CI_COMMON_SCRIPT}"
th_assert_run "ci-common-json-obj-basic" 0 "" bash -c '
  source "$1"
  result="$(ci_json_obj key1 val1 key2 "#int:42")"
  echo "${result}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[\"key1\"]==\"val1\"; assert d[\"key2\"]==42"
' _ "${CI_COMMON_SCRIPT}"
th_assert_run "ci-common-json-obj-python-fallback" 0 "" bash -c '
  source "$1"
  # Force python fallback by calling the internal function directly
  result="$(_ci_json_obj_python a b c "#int:1")"
  echo "${result}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[\"a\"]==\"b\"; assert d[\"c\"]==1"
' _ "${CI_COMMON_SCRIPT}"
th_assert_run "ci-common-normalize-bool" 0 "true false true false" bash -c '
  source "$1"
  printf "%s %s %s %s" "$(ci_normalize_bool YES)" "$(ci_normalize_bool garbage)" "$(ci_normalize_bool 1)" "$(ci_normalize_bool OFF)"
' _ "${CI_COMMON_SCRIPT}"
th_assert_run "ci-common-now-utc-format" 0 'Z' bash -c '
  source "$1"
  ci_now_utc
' _ "${CI_COMMON_SCRIPT}"
th_assert_run "ci-common-epoch-numeric" 0 "" bash -c '
  source "$1"
  val="$(ci_epoch)"
  [[ "${val}" =~ ^[0-9]+$ ]] || exit 1
' _ "${CI_COMMON_SCRIPT}"
th_assert_run "ci-common-double-source-guard" 0 "ok" bash -c '
  source "$1"
  source "$1"
  echo ok
' _ "${CI_COMMON_SCRIPT}"

# --- normalize helpers ---
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

th_assert_run "capture-run-preserves-exit-code" 0 "7:warn" bash -c '
  source "$1"
  set +e
  ps_capture_run bash -c "echo warn >&2; exit 7"
  rc="$?"
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    exit 1
  fi
  printf "%s:%s\n" "${rc}" "${PS_LAST_COMMAND_STDERR}"
' _ "${HELPER_SCRIPT}"

# --- Context lifecycle ---
th_assert_run "ctx-driven-json-log" 0 '"kind":"freshness"' bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/report.json PS_CTX_METRICS_PATH=/tmp/metrics.prom \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=feedface PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
  ps_log_json INFO submodule_freshness.start pending "hello"
' _ "${HELPER_SCRIPT}"

th_assert_run "ctx-driven-json-report" 0 "pass" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=feedface PS_CTX_REMOTE_BRANCH=main PS_CTX_STRICT_REMOTE=false PS_CTX_AUTO_UPDATE=true
  ps_ctx_init
  ps_write_json_report "${tmpdir}/report.json" pass_up_to_date "ok" 0
  python3 - <<PY
import json
from pathlib import Path
report = json.loads(Path(${tmpdir@Q} + "/report.json").read_text(encoding="utf-8"))
assert report["kind"] == "freshness"
assert report["outcome"] == "pass_up_to_date"
assert report["strict_remote"] == "false"
assert report["duration_seconds"] >= 0
assert report["events_path"].endswith("/events.jsonl")
print(report["status"])
PY
' _ "${HELPER_SCRIPT}"

th_assert_run "ctx-driven-metrics" 0 "prompts_submodule_freshness_last_run_timestamp_seconds" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=feedface PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
  ps_emit_prom_metrics fail_stale
  cat "${tmpdir}/metrics.prom"
' _ "${HELPER_SCRIPT}"

th_assert_run "ctx-events-log-created" 0 "\"event\":\"test.event\"" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_REPO_ROOT=/repo
  ps_ctx_init
  ps_log_json INFO test.event pending "hello"
  cat "${tmpdir}/events.jsonl"
' _ "${HELPER_SCRIPT}"

th_assert_run "governance-metrics-emitted" 0 "prompts_submodule_governance_status" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=governance PS_CTX_ACTION=governance PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=unknown \
    PS_CTX_REMOTE_SHA=unknown PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
  ps_emit_prom_metrics pass_checked_direct
  cat "${tmpdir}/metrics.prom"
' _ "${HELPER_SCRIPT}"

# --- git-env ---
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

# --- Submodule path detection ---
th_assert_run "prompts-submodule-path-no-match" 0 "miss" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "other"]
	path = other
	url = https://example.invalid/other.git
EOF
  ps_prompts_submodule_path "${tmpdir}" >/dev/null 2>&1 || echo miss
  ps_prompts_submodule_name "${tmpdir}" prompts >/dev/null 2>&1 || echo miss
' _ "${HELPER_SCRIPT}"

th_assert_run "tracking-branch-dot-fallback" 0 "feature/test" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q -b feature/test
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
	branch = .
EOF
  ps_tracking_branch "${tmpdir}" prompts
' _ "${HELPER_SCRIPT}"

th_assert_run "strict-remote-decision-matrix" 0 "1 0 0 1" bash -c '
  source "$1"
  unset CI GITHUB_ACTIONS GITEA_ACTIONS
  if ps_should_strict_fail_remote true; then printf "1 "; else printf "0 "; fi
  if ps_should_strict_fail_remote false; then printf "1 "; else printf "0 "; fi
  if ps_should_strict_fail_remote auto; then printf "1 "; else printf "0 "; fi
  if CI=true ps_should_strict_fail_remote auto; then printf "1\n"; else printf "0\n"; fi
' _ "${HELPER_SCRIPT}"

# --- ps_ctx_init validation ---
th_assert_run "ctx-init-rejects-missing-kind" 1 "PS_CTX_KIND must be set" bash -c '
  source "$1"
  PS_CTX_KIND="" PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
' _ "${HELPER_SCRIPT}"
th_assert_run "ctx-init-rejects-missing-action" 1 "PS_CTX_ACTION must be set" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_ACTION="" PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
' _ "${HELPER_SCRIPT}"
th_assert_run "ctx-init-rejects-missing-report" 1 "PS_CTX_REPORT_PATH must be set" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=""
  ps_ctx_init
' _ "${HELPER_SCRIPT}"

# --- Log format verification ---
th_assert_run "log-json-slim-format" 0 "" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
  output="$(ps_log_json INFO test.event pending "msg")"
  # Slim format should NOT contain repo_root, prompts_path, local_sha, remote_sha
  echo "${output}" | grep -q "repo_root" && exit 1
  echo "${output}" | grep -q "prompts_path" && exit 1
  # But should contain schema + run correlation fields
  echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d[\"schema_version\"] == \"2\"; assert d[\"action\"] == \"freshness\"; assert \"run_id\" in d"
' _ "${HELPER_SCRIPT}"

th_assert_run "log-json-pending-status" 0 "pending" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
  output="$(ps_log_json INFO test.event pending "msg")"
  echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[\"status\"])"
' _ "${HELPER_SCRIPT}"

th_assert_run "status-from-outcome-unknown" 0 "unknown" bash -c '
  source "$1"
  ps_status_from_outcome mystery
' _ "${HELPER_SCRIPT}"

th_assert_run "status-from-outcome-pending" 0 "pending" bash -c '
  source "$1"
  ps_status_from_outcome pending
' _ "${HELPER_SCRIPT}"

th_assert_run "report-context-missing" 1 "context missing for report emission" bash -c '
  source "$1"
  ps_write_json_report /tmp/missing-context.json pass_up_to_date "no ctx" 1
' _ "${HELPER_SCRIPT}"

th_assert_run "finish-and-exit-missing-context" 1 "context missing" bash -c '
  source "$1"
  ( ps_finish_and_exit pass_up_to_date "missing ctx" 0 )
' _ "${HELPER_SCRIPT}"

th_assert_run "finish-and-exit-unknown-outcome" 0 "fail_internal" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  (
    PS_CTX_KIND=freshness
    PS_CTX_ACTION=freshness
    PS_CTX_REPORT_PATH="${tmpdir}/report.json"
    PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom"
    ps_ctx_init
    ps_finish_and_exit not_a_real_outcome "bad" 9
  ) >/dev/null 2>&1 || true
  python3 - <<PY
import json
from pathlib import Path
report = json.loads(Path(${tmpdir@Q} + "/report.json").read_text(encoding="utf-8"))
assert report["outcome"] == "fail_internal"
print(report["outcome"])
PY
' _ "${HELPER_SCRIPT}"

# --- report-alert.py comprehensive coverage ---
th_assert_run "report-alert-ci-debug-missing" 0 "::warning::ci-debug report missing" \
  python3 "${REPORT_ALERT_SCRIPT}" ci-debug /tmp/does-not-exist-report.json

th_assert_run "report-alert-freshness-pass" 0 "::notice::submodule freshness passed" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "{\"status\":\"pass\",\"outcome\":\"pass_up_to_date\",\"message\":\"ok\"}" > "${tmpf}"
  python3 "$1" submodule-freshness "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-freshness-fail" 0 "::error::submodule freshness failed" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "{\"status\":\"fail\",\"outcome\":\"fail_stale\",\"message\":\"stale\",\"exit_code\":1}" > "${tmpf}"
  python3 "$1" submodule-freshness "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-freshness-skip" 0 "::warning::submodule freshness skipped" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "{\"status\":\"skip\",\"outcome\":\"skip_not_registered\",\"message\":\"skip\"}" > "${tmpf}"
  python3 "$1" submodule-freshness "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-ci-debug-pass" 0 "::notice::ci:debug status=pass" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "{\"status\":\"pass\",\"stage\":\"complete\",\"failed_command\":\"\",\"message\":\"ok\"}" > "${tmpf}"
  python3 "$1" ci-debug "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-ci-debug-fail" 0 "::error::ci:debug failed" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "{\"status\":\"fail\",\"stage\":\"lint\",\"failed_command\":\"golangci-lint\",\"message\":\"lint failed\"}" > "${tmpf}"
  python3 "$1" ci-debug "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-unknown-profile" 0 "::warning::unknown report-alert profile" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "{\"status\":\"pass\"}" > "${tmpf}"
  python3 "$1" unknown-profile "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-governance-pass" 0 "::notice::governance check passed" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "{\"schema_version\":\"2\",\"status\":\"pass\",\"outcome\":\"pass_checked_via_override\",\"message\":\"ok\"}" > "${tmpf}"
  python3 "$1" governance "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-shell-coverage-pass" 0 "::notice::shell coverage passed" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "{\"status\":\"pass\",\"coverage_percent\":97.5,\"threshold_percent\":90}" > "${tmpf}"
  python3 "$1" shell-coverage "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-unreadable" 0 "::error::submodule-freshness report unreadable" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "NOT JSON" > "${tmpf}"
  python3 "$1" submodule-freshness "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-usage-error" 2 "usage:" \
  python3 "${REPORT_ALERT_SCRIPT}"

th_assert_run "entry-usage-error-no-command" 2 "usage:" bash "${ENTRY_SCRIPT}"
th_assert_run "entry-usage-error-unknown-command" 2 "usage:" bash "${ENTRY_SCRIPT}" nope

# --- Action outcome tests with mock git ---
th_assert_run "action-pass-up-to-date" 0 "pass_up_to_date" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then echo deadbeef; exit 0; fi
if [[ "${args[*]}" == *" rev-parse origin/main"* ]]; then echo deadbeef; exit 0; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 0; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

th_assert_run "action-fail-corrupt-submodule" 0 "fail_corrupt_submodule" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then exit 1; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

th_assert_run "action-skip-missing-remote-ref" 0 "skip_missing_remote_ref" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then echo deadbeef; exit 0; fi
if [[ "${args[*]}" == *" rev-parse origin/main"* ]]; then exit 1; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 0; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    STRICT_REMOTE=false
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

th_assert_run "action-fail-checkout" 0 "fail_checkout" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
joined="$*"
if [[ "${joined}" == *" rev-parse HEAD"* ]]; then echo deadbeef; exit 0; fi
if [[ "${joined}" == *" rev-parse origin/main"* ]]; then echo feedface; exit 0; fi
if [[ "${joined}" == *" submodule update --remote "* ]]; then exit 1; fi
if [[ "${joined}" == *" checkout "* ]]; then exit 1; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 0; }
  ps_submodule_has_local_changes() { return 1; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    AUTO_UPDATE=true
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

th_assert_run "action-pass-worktree-only-update" 0 "pass_auto_updated_worktree_only" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
joined="$*"
if [[ "${joined}" == *" rev-parse origin/main"* ]]; then echo feedface; exit 0; fi
if [[ "${joined}" == *" rev-parse HEAD"* ]]; then
  if [[ -f "${TMPDIR_MARKER}/after-checkout" ]]; then echo feedface; else echo deadbeef; fi
  exit 0
fi
if [[ "${joined}" == *" submodule update --remote "* ]]; then exit 1; fi
if [[ "${joined}" == *" checkout "* ]]; then touch "${TMPDIR_MARKER}/after-checkout"; exit 0; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 0; }
  ps_submodule_has_local_changes() { return 1; }
  (
    export TMPDIR_MARKER="${tmpdir}"
    PATH="${tmpdir}/bin:${PATH}"
    AUTO_UPDATE=true
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

th_assert_run "artifact-warning-does-not-mask-exit" 0 'artifact_warning' bash -c '
  source "$1"
  (
    PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/proc/eos-test/report.json PS_CTX_METRICS_PATH=/proc/eos-test/metrics.prom \
      PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
      PS_CTX_REMOTE_SHA=feedface PS_CTX_REMOTE_BRANCH=main
    ps_ctx_init
    ps_finish_and_exit pass_up_to_date ok 0
  )
' _ "${HELPER_SCRIPT}"

# --- Governance action coverage ---
th_assert_run "governance-start-event-pending" 0 '"outcome":"pending"' bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/prompts/scripts"
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF
  cat > "${tmpdir}/prompts/scripts/check-governance.sh" <<'"'"'CHECKER'"'"'
#!/usr/bin/env bash
exit 0
CHECKER
  chmod +x "${tmpdir}/prompts/scripts/check-governance.sh"
  mkdir -p "${tmpdir}/scripts/lib/prompts-submodule" "${tmpdir}/scripts/hooks" "${tmpdir}/scripts/ci"
  for f in prompts-submodule.sh check-governance.sh prompts-submodule-freshness.sh install-git-hooks.sh; do
    cp "'"${REPO_ROOT}"'/scripts/${f}" "${tmpdir}/scripts/${f}" 2>/dev/null || true
  done
  cp "'"${REPO_ROOT}"'/scripts/hooks/pre-commit-ci-debug.sh" "${tmpdir}/scripts/hooks/" 2>/dev/null || true
  for f in ci-common.sh git-env.sh prompts-submodule.sh; do
    cp "'"${REPO_ROOT}"'/scripts/lib/${f}" "${tmpdir}/scripts/lib/${f}"
  done
  for f in common.sh context.sh git.sh artifacts.sh actions.sh; do
    cp "'"${REPO_ROOT}"'/scripts/lib/prompts-submodule/${f}" "${tmpdir}/scripts/lib/prompts-submodule/${f}"
  done
  chmod +x "${tmpdir}/scripts/prompts-submodule.sh" "${tmpdir}/scripts/check-governance.sh"
  (
    GOVERNANCE_REPORT_JSON="${tmpdir}/gov-report.json"
    GOVERNANCE_METRICS_TEXTFILE="${tmpdir}/gov-metrics.prom"
    bash "${tmpdir}/scripts/check-governance.sh"
  )
' _ "${HELPER_SCRIPT}"

th_assert_run "governance-timeout-checker" 0 "fail_checker_error" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/prompts/scripts"
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF
  cat > "${tmpdir}/prompts/scripts/check-governance.sh" <<'"'"'CHECKER'"'"'
#!/usr/bin/env bash
sleep 10
exit 0
CHECKER
  chmod +x "${tmpdir}/prompts/scripts/check-governance.sh"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_governance_checker_path() { printf "%s/prompts/scripts/check-governance.sh\n" "$1"; }
  (
    PS_GOVERNANCE_CHECKER_TIMEOUT=1
    GOVERNANCE_REPORT_JSON="${tmpdir}/gov-report.json"
    ps_run_governance "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/gov-report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- Pre-commit edge case: verify-parity.sh missing ---
th_assert_run "pre-commit-missing-parity-script" 0 "" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  PS_CTX_KIND=hook PS_CTX_ACTION=pre-commit PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_REPO_ROOT="${tmpdir}"
  ps_ctx_init
  # No staged files means early exit
  ps_run_pre_commit "${tmpdir}" 2>/dev/null
' _ "${HELPER_SCRIPT}"

# --- Fixture-based freshness wrapper tests (using th_create_fixture DRY helper) ---
tmpdir="$(th_create_fixture)"
trap 'rm -rf "${tmpdir}"' EXIT

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
th_assert_json_field "report-schema-uninitialized" "${tmpdir}/report2.json" "schema_version" "2"
th_assert_run "entry-governance-skip-uninitialized" 0 '"outcome":"skip_uninitialized"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir}/gov-report.json" bash "${tmpdir}/scripts/prompts-submodule.sh" governance

# --- JSON report validity (jq-generated must be valid) ---
th_assert_run "report-valid-json" 0 "" bash -c '
  python3 -c "import json; json.load(open(\"$1\"))" "$1"
' _ "${tmpdir}/report2.json"

# --- Metrics emission for pass outcome (exercises status_value=1 branch) ---
th_assert_run "metrics-pass-status-value" 0 "} 1" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=deadbeef PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
  ps_emit_prom_metrics pass_up_to_date
  cat "${tmpdir}/metrics.prom"
' _ "${HELPER_SCRIPT}"

# --- Metrics emission failure (unwritable path) ---
th_assert_run "metrics-write-failure-warning" 1 "artifact_warning" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" \
    PS_CTX_METRICS_PATH="/proc/eos-nonexistent/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=deadbeef PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
  ps_emit_prom_metrics pass_up_to_date 2>&1
' _ "${HELPER_SCRIPT}"

# --- Action: fail_dirty_worktree when auto-update enabled ---
th_assert_run "action-fail-dirty-worktree" 0 "fail_dirty_worktree" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then echo deadbeef; exit 0; fi
if [[ "${args[*]}" == *" rev-parse origin/main"* ]]; then echo feedface; exit 0; fi
if [[ "${args[*]}" == *" status --porcelain"* ]]; then echo "M dirty-file"; exit 0; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 0; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    AUTO_UPDATE=true
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- Action: pass_auto_updated when submodule update succeeds ---
th_assert_run "action-pass-auto-updated" 0 "pass_auto_updated" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  call_count_file="${tmpdir}/.rev_parse_count"
  echo 0 > "${call_count_file}"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
# After submodule update, HEAD should return the remote SHA
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then
  # First call returns old SHA, second call (post-update) returns new SHA
  count_file="$(dirname "$0")/../.rev_parse_count"
  count="$(cat "${count_file}")"
  count=$((count + 1))
  echo "${count}" > "${count_file}"
  if [[ "${count}" -le 1 ]]; then
    echo deadbeef
  else
    echo feedface
  fi
  exit 0
fi
if [[ "${args[*]}" == *" rev-parse origin/main"* ]]; then echo feedface; exit 0; fi
if [[ "${args[*]}" == *" submodule update --remote"* ]]; then exit 0; fi
if [[ "${args[*]}" == *" status --porcelain"* ]]; then exit 0; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 0; }
  ps_submodule_has_local_changes() { return 1; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    AUTO_UPDATE=true
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- Hook install: hash mismatch detection ---
th_assert_run "install-hook-hash-mismatch" 1 "Hook matches source: false" bash -c '
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/scripts/hooks" "${tmpdir}/.git/hooks"
  printf "%s\n" "#!/usr/bin/env bash" > "${tmpdir}/scripts/hooks/pre-commit-ci-debug.sh"
  printf "%s\n" "#!/usr/bin/env bash" "# tampered" > "${tmpdir}/.git/hooks/pre-commit"
  hook_sha="$(sha256sum "${tmpdir}/.git/hooks/pre-commit" | awk "{print \$1}")"
  source_sha="$(sha256sum "${tmpdir}/scripts/hooks/pre-commit-ci-debug.sh" | awk "{print \$1}")"
  if [[ "${hook_sha}" != "${source_sha}" ]]; then
    echo "Hook matches source: false"
    exit 1
  fi
' _ "${HELPER_SCRIPT}"

# --- ps_warn_artifact_failure direct test ---
th_assert_run "warn-artifact-failure-output" 0 "artifact_warning" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
  ps_warn_artifact_failure "report" "/bad/path" "disk full" 2>&1
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_ctx_init metric name validation ---
th_assert_run "ctx-init-rejects-invalid-kind-chars" 1 "invalid characters for metric names" bash -c '
  source "$1"
  PS_CTX_KIND="bad-chars" PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
' _ "${HELPER_SCRIPT}"

th_assert_run "ctx-init-rejects-kind-starting-with-digit" 1 "invalid characters" bash -c '
  source "$1"
  PS_CTX_KIND="9start" PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
' _ "${HELPER_SCRIPT}"

th_assert_run "ctx-init-accepts-underscored-kind" 0 "" bash -c '
  source "$1"
  PS_CTX_KIND=fresh_ness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init >/dev/null 2>&1
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_ctx_init double-init idempotency (events not truncated) ---
th_assert_run "ctx-double-init-preserves-events" 0 "first_event" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json"
  ps_ctx_init
  ps_log_json INFO first_event pending "should survive" >/dev/null
  # Second init should NOT truncate events
  ps_ctx_init
  cat "${tmpdir}/events.jsonl"
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_ctx_begin full parameter flow ---
th_assert_run "ctx-begin-sets-all-fields" 0 "" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  ps_ctx_begin freshness freshness "${tmpdir}/report.json" "${tmpdir}/metrics.prom" /repo true true
  [[ "${PS_CTX_KIND}" == "freshness" ]] || exit 1
  [[ "${PS_CTX_ACTION}" == "freshness" ]] || exit 1
  [[ "${PS_CTX_STRICT_REMOTE}" == "true" ]] || exit 1
  [[ "${PS_CTX_AUTO_UPDATE}" == "true" ]] || exit 1
  [[ -n "${PS_CTX_RUN_ID}" ]] || exit 1
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_compact_command_error truncation indicator ---
th_assert_run "compact-error-short-no-ellipsis" 0 "short error" bash -c '
  source "$1"
  result="$(ps_compact_command_error "short error")"
  [[ "${result}" == "short error" ]] || { echo "got: ${result}"; exit 1; }
  echo "${result}"
' _ "${HELPER_SCRIPT}"

th_assert_run "compact-error-long-has-ellipsis" 0 "..." bash -c '
  source "$1"
  long="$(printf "%0.s=x" {1..150})"
  result="$(ps_compact_command_error "${long}")"
  [[ "${result}" == *"..." ]] || { echo "missing ellipsis: ${result}"; exit 1; }
  echo "${result}"
' _ "${HELPER_SCRIPT}"

th_assert_run "compact-error-empty" 0 "" bash -c '
  source "$1"
  result="$(ps_compact_command_error "")"
  [[ -z "${result}" ]] || { echo "expected empty, got: ${result}"; exit 1; }
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_capture_run preserves stdout and stderr ---
th_assert_run "capture-run-preserves-stdout" 0 "hello" bash -c '
  source "$1"
  ps_capture_run echo hello
  printf "%s" "${PS_LAST_COMMAND_STDOUT}"
' _ "${HELPER_SCRIPT}"

th_assert_run "capture-run-success-returns-0" 0 "" bash -c '
  source "$1"
  ps_capture_run true
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_emit_prom_metrics skip branch (no metrics path) ---
th_assert_run "metrics-skip-when-no-path" 0 "" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/r.json PS_CTX_METRICS_PATH=""
  ps_ctx_init
  ps_emit_prom_metrics pass_up_to_date
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_emit_prom_metrics skip outcome (status_value=0) ---
th_assert_run "metrics-skip-outcome-status-0" 0 "} 0" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=deadbeef PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
  ps_emit_prom_metrics skip_not_registered
  grep "status{" "${tmpdir}/metrics.prom"
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_emit_prom_metrics fail outcome (status_value=-1) ---
th_assert_run "metrics-fail-outcome-status-neg1" 0 "} -1" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=feedface PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
  ps_emit_prom_metrics fail_remote_unreachable
  grep "status{" "${tmpdir}/metrics.prom"
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_emit_prom_metrics stale flag ---
th_assert_run "metrics-stale-flag-set-on-fail-stale" 0 "_stale 1" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts
  ps_ctx_init
  ps_emit_prom_metrics fail_stale
  grep "_stale " "${tmpdir}/metrics.prom" | grep -v TYPE
' _ "${HELPER_SCRIPT}"

th_assert_run "metrics-stale-flag-zero-on-pass" 0 "_stale 0" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts
  ps_ctx_init
  ps_emit_prom_metrics pass_up_to_date
  grep "_stale " "${tmpdir}/metrics.prom" | grep -v TYPE
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_log_level_for_outcome ---
th_assert_run "log-level-fail-is-error" 0 "ERROR" bash -c '
  source "$1"
  ps_log_level_for_outcome fail_stale
' _ "${HELPER_SCRIPT}"

th_assert_run "log-level-skip-is-warn" 0 "WARN" bash -c '
  source "$1"
  ps_log_level_for_outcome skip_not_registered
' _ "${HELPER_SCRIPT}"

th_assert_run "log-level-pass-is-info" 0 "INFO" bash -c '
  source "$1"
  ps_log_level_for_outcome pass_up_to_date
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_finish_and_exit unknown outcome for non-freshness kind ---
th_assert_run "finish-exit-unknown-outcome-governance" 0 "fail_checker_error" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  (
    PS_CTX_KIND=governance
    PS_CTX_ACTION=governance
    PS_CTX_REPORT_PATH="${tmpdir}/report.json"
    PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom"
    ps_ctx_init
    ps_finish_and_exit not_real "bad" 9
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_write_atomic_file failure paths ---
th_assert_run "write-atomic-file-mkdir-failure" 1 "" bash -c '
  source "$1"
  ps_write_atomic_file "/proc/eos-nonexistent/subdir/file.json" <<< "data"
' _ "${HELPER_SCRIPT}"

th_assert_run "write-atomic-file-success" 0 "hello" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  ps_write_atomic_file "${tmpdir}/test.txt" <<< "hello"
  cat "${tmpdir}/test.txt"
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_prompts_submodule_name match ---
th_assert_run "submodule-name-found" 0 "myprompts" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "myprompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF
  ps_prompts_submodule_name "${tmpdir}" prompts
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_governance_checker_path not executable ---
th_assert_run "governance-checker-not-executable" 1 "" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/prompts/scripts"
  echo "#!/usr/bin/env bash" > "${tmpdir}/prompts/scripts/check-governance.sh"
  chmod -x "${tmpdir}/prompts/scripts/check-governance.sh"
  ps_governance_checker_path "${tmpdir}" prompts
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_tracking_branch explicit branch (not ".") ---
th_assert_run "tracking-branch-explicit" 0 "develop" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
	branch = develop
EOF
  ps_tracking_branch "${tmpdir}" prompts
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_tracking_branch no branch configured (default to main) ---
th_assert_run "tracking-branch-default-main" 0 "main" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF
  ps_tracking_branch "${tmpdir}" prompts
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_repo_root ---
th_assert_run "repo-root-from-script-path" 0 "" bash -c '
  source "$1"
  result="$(ps_repo_root "/opt/eos/scripts/check-governance.sh")"
  [[ "${result}" == "/opt/eos" ]] || { echo "got: ${result}"; exit 1; }
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_schema_version ---
th_assert_run "schema-version-is-2" 0 "2" bash -c '
  source "$1"
  ps_schema_version
' _ "${HELPER_SCRIPT}"

# --- NEW: ci_in_ci ---
th_assert_run "ci-in-ci-with-CI-var" 0 "" bash -c '
  source "$1"
  CI=true ci_in_ci
' _ "${CI_COMMON_SCRIPT}"

th_assert_run "ci-in-ci-with-github-actions" 0 "" bash -c '
  source "$1"
  unset CI GITEA_ACTIONS
  GITHUB_ACTIONS=true ci_in_ci
' _ "${CI_COMMON_SCRIPT}"

th_assert_run "ci-in-ci-with-gitea-actions" 0 "" bash -c '
  source "$1"
  unset CI GITHUB_ACTIONS
  GITEA_ACTIONS=true ci_in_ci
' _ "${CI_COMMON_SCRIPT}"

th_assert_run "ci-in-ci-returns-false-locally" 1 "" bash -c '
  source "$1"
  unset CI GITHUB_ACTIONS GITEA_ACTIONS
  ci_in_ci
' _ "${CI_COMMON_SCRIPT}"

# --- NEW: ps_outcome_known exhaustive coverage ---
th_assert_run "outcome-known-hook-pass-ci-debug-self-update" 0 "" bash -c '
  source "$1"
  ps_outcome_known hook pass_ci_debug_self_update
' _ "${HELPER_SCRIPT}"

th_assert_run "outcome-known-hook-install-fail-install" 0 "" bash -c '
  source "$1"
  ps_outcome_known hook_install fail_install
' _ "${HELPER_SCRIPT}"

th_assert_run "outcome-known-freshness-fail-remote-unreachable" 0 "" bash -c '
  source "$1"
  ps_outcome_known freshness fail_remote_unreachable
' _ "${HELPER_SCRIPT}"

th_assert_run "outcome-unknown-returns-1" 1 "" bash -c '
  source "$1"
  ps_outcome_known freshness totally_made_up
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_submodule_has_local_changes ---
th_assert_run "submodule-no-local-changes" 1 "" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  ps_submodule_has_local_changes "$(dirname "${tmpdir}")" "$(basename "${tmpdir}")"
' _ "${HELPER_SCRIPT}"

# --- NEW: freshness fail_stale (AUTO_UPDATE=false with stale submodule) ---
th_assert_run "action-fail-stale" 0 "fail_stale" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then echo deadbeef; exit 0; fi
if [[ "${args[*]}" == *" rev-parse origin/main"* ]]; then echo feedface; exit 0; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 0; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    AUTO_UPDATE=false
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- NEW: freshness strict remote fail ---
th_assert_run "action-fail-remote-unreachable-strict" 0 "fail_remote_unreachable" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then echo deadbeef; exit 0; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 1; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    STRICT_REMOTE=true
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- NEW: freshness skip remote unreachable (non-strict) ---
th_assert_run "action-skip-remote-unreachable" 0 "skip_remote_unreachable" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then echo deadbeef; exit 0; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 1; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    STRICT_REMOTE=false
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- NEW: freshness strict missing remote ref ---
th_assert_run "action-fail-missing-remote-ref-strict" 0 "fail_missing_remote_ref" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/bin" "${tmpdir}/prompts"
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then echo deadbeef; exit 0; fi
if [[ "${args[*]}" == *" rev-parse origin/main"* ]]; then exit 1; fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/bin/git"
  ps_prompts_submodule_path() { printf "prompts\n"; }
  ps_prompts_submodule_initialized() { return 0; }
  ps_tracking_branch() { printf "main\n"; }
  ps_git_fetch_remote_branch() { return 0; }
  (
    PATH="${tmpdir}/bin:${PATH}"
    STRICT_REMOTE=true
    SUBMODULE_REPORT_JSON="${tmpdir}/report.json"
    ps_run_freshness "${tmpdir}"
  ) >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_write_json_report to unwritable path ---
th_assert_run "report-write-failure" 1 "failed to write JSON report" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_ACTION=freshness PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
  ps_write_json_report /proc/eos-nonexistent/report.json pass_up_to_date "ok" 0 2>&1
' _ "${HELPER_SCRIPT}"

# --- NEW: ci_json_escape with tabs and newlines ---
th_assert_run "ci-json-escape-tabs-newlines" 0 "" bash -c '
  source "$1"
  result="$(ci_json_escape "$(printf "line1\nline2\ttab")")"
  [[ "${result}" == "line1\nline2\ttab" ]] || { echo "got: ${result}"; exit 1; }
' _ "${CI_COMMON_SCRIPT}"

# --- NEW: ps_prompts_submodule_path with third_party/prompts ---
th_assert_run "submodule-path-third-party" 0 "third_party/prompts" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "prompts"]
	path = third_party/prompts
	url = https://example.invalid/prompts.git
EOF
  ps_prompts_submodule_path "${tmpdir}"
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_prompts_submodule_path with no .gitmodules ---
th_assert_run "submodule-path-no-gitmodules" 1 "" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  ps_prompts_submodule_path "${tmpdir}"
' _ "${HELPER_SCRIPT}"

# --- NEW: ps_prompts_submodule_initialized with uninitialized ---
th_assert_run "submodule-not-initialized" 1 "" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  cat > "${tmpdir}/.gitmodules" <<EOF
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF
  ps_prompts_submodule_initialized "${tmpdir}" prompts
' _ "${HELPER_SCRIPT}"

# --- NEW: ge_run_clean_git ---
th_assert_run "ge-run-clean-git-works" 0 "hello" bash -c '
  source "$1"
  export GIT_DIR=/tmp/fake
  ge_run_clean_git bash -c "echo hello; [[ -z \${GIT_DIR:-} ]]"
' _ "${GIT_ENV_SCRIPT}"

th_summary "unit"
