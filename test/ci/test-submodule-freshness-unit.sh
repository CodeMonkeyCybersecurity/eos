#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

FRESHNESS_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule-freshness.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
CI_COMMON_SCRIPT="${REPO_ROOT}/scripts/lib/ci-common.sh"
GIT_ENV_SCRIPT="${REPO_ROOT}/scripts/lib/git-env.sh"
REPORT_ALERT_SCRIPT="${REPO_ROOT}/scripts/ci/report-alert.py"

th_assert_run "freshness-script-syntax" 0 "" bash -n "${FRESHNESS_SCRIPT}"
th_assert_run "helper-script-syntax" 0 "" bash -n "${HELPER_SCRIPT}"
th_assert_run "ci-common-script-syntax" 0 "" bash -n "${CI_COMMON_SCRIPT}"
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
  PS_CTX_KIND=freshness PS_CTX_REPORT_PATH=/tmp/report.json PS_CTX_METRICS_PATH=/tmp/metrics.prom \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=feedface PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
  ps_log_json INFO submodule_freshness.start skip_not_registered "hello"
' _ "${HELPER_SCRIPT}"
th_assert_run "ctx-driven-json-report" 0 "pass" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
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
print(report["status"])
PY
' _ "${HELPER_SCRIPT}"
th_assert_run "ctx-driven-metrics" 0 "prompts_submodule_freshness_last_run_timestamp_seconds" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  PS_CTX_KIND=freshness PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_METRICS_PATH="${tmpdir}/metrics.prom" \
    PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
    PS_CTX_REMOTE_SHA=feedface PS_CTX_REMOTE_BRANCH=main
  ps_ctx_init
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

# --- ci-common.sh shared primitives ---
th_assert_run "ci-common-json-escape" 0 'hello\"world' bash -c '
  source "$1"
  ci_json_escape "hello\"world"
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
th_assert_run "ctx-init-rejects-missing-report" 1 "PS_CTX_REPORT_PATH must be set" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_REPORT_PATH=""
  ps_ctx_init
' _ "${HELPER_SCRIPT}"

# --- Slim log format verification ---
th_assert_run "log-json-slim-format" 0 "" bash -c '
  source "$1"
  PS_CTX_KIND=freshness PS_CTX_REPORT_PATH=/tmp/r.json
  ps_ctx_init
  output="$(ps_log_json INFO test.event pass_up_to_date "msg")"
  # Slim format should NOT contain repo_root, prompts_path, local_sha, remote_sha
  echo "${output}" | grep -q "repo_root" && exit 1
  echo "${output}" | grep -q "prompts_path" && exit 1
  # But should contain the 7 expected fields
  echo "${output}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert len(d)==7, f\"expected 7 fields, got {len(d)}\""
' _ "${HELPER_SCRIPT}"

th_assert_run "status-from-outcome-unknown" 0 "unknown" bash -c '
  source "$1"
  ps_status_from_outcome mystery
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

th_assert_run "report-alert-unreadable" 0 "::error::submodule-freshness report unreadable" bash -c '
  tmpf="$(mktemp)"
  trap "rm -f \"${tmpf}\"" EXIT
  echo "NOT JSON" > "${tmpf}"
  python3 "$1" submodule-freshness "${tmpf}"
' _ "${REPORT_ALERT_SCRIPT}"

th_assert_run "report-alert-usage-error" 2 "usage:" \
  python3 "${REPORT_ALERT_SCRIPT}"

th_assert_run "wrapper-pass-up-to-date" 0 "pass_up_to_date" bash -c '
  wrapper_src="$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/scripts/lib" "${tmpdir}/bin" "${tmpdir}/prompts"
  cp "${wrapper_src}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
  cat > "${tmpdir}/scripts/lib/prompts-submodule.sh" <<'"'"'EOF_HELPER'"'"'
#!/usr/bin/env bash
set -Eeuo pipefail
PS_CTX_KIND="${PS_CTX_KIND:-}"
PS_CTX_REPORT_PATH="${PS_CTX_REPORT_PATH:-}"
PS_CTX_METRICS_PATH="${PS_CTX_METRICS_PATH:-}"
PS_CTX_REPO_ROOT="${PS_CTX_REPO_ROOT:-}"
PS_CTX_PROMPTS_PATH="${PS_CTX_PROMPTS_PATH:-}"
PS_CTX_LOCAL_SHA="${PS_CTX_LOCAL_SHA:-unknown}"
PS_CTX_REMOTE_SHA="${PS_CTX_REMOTE_SHA:-unknown}"
PS_CTX_REMOTE_BRANCH="${PS_CTX_REMOTE_BRANCH:-unknown}"
PS_CTX_STRICT_REMOTE="${PS_CTX_STRICT_REMOTE:-auto}"
PS_CTX_AUTO_UPDATE="${PS_CTX_AUTO_UPDATE:-false}"
ps_repo_root() { cd "$(dirname "$1")/.." && pwd; }
ps_ctx_init() { : "${PS_CTX_KIND:?}"; : "${PS_CTX_REPORT_PATH:?}"; }
ps_log_json() { :; }
ps_prompts_submodule_path() { printf "prompts\n"; }
ps_prompts_submodule_initialized() { return 0; }
ps_tracking_branch() { printf "main\n"; }
ps_git_fetch_remote_branch() { return "${FAKE_FETCH_RC:-0}"; }
ps_should_strict_fail_remote() { [[ "${1:-auto}" == "true" ]]; }
ps_submodule_has_local_changes() { [[ "${FAKE_DIRTY:-false}" == "true" ]]; }
ps_finish_and_exit() {
  mkdir -p "$(dirname "${PS_CTX_REPORT_PATH}")"
  printf "{\"kind\":\"%s\",\"outcome\":\"%s\"}\n" "${PS_CTX_KIND}" "$1" > "${PS_CTX_REPORT_PATH}"
  exit "${3:-0}"
}
EOF_HELPER
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then
  printf "%s\n" "${FAKE_HEAD_SHA:-deadbeef}"
  exit 0
fi
if [[ "${args[*]}" == *" rev-parse origin/main"* ]]; then
  printf "%s\n" "${FAKE_REMOTE_SHA:-deadbeef}"
  exit 0
fi
if [[ "${args[*]}" == *" submodule update --remote -- prompts"* ]]; then
  exit "${FAKE_SUBMODULE_UPDATE_RC:-0}"
fi
if [[ "${args[*]}" == *" checkout --detach "* ]]; then
  exit "${FAKE_CHECKOUT_RC:-0}"
fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh" "${tmpdir}/bin/git"
  PATH="${tmpdir}/bin:${PATH}" SUBMODULE_REPORT_JSON="${tmpdir}/report.json" \
    bash "${tmpdir}/scripts/prompts-submodule-freshness.sh" >/dev/null 2>&1
  python3 - <<PY
import json
from pathlib import Path
report = json.loads(Path(${tmpdir@Q} + "/report.json").read_text(encoding="utf-8"))
print(report["outcome"])
PY
' _ "${FRESHNESS_SCRIPT}"

th_assert_run "wrapper-fail-corrupt-submodule" 0 "fail_corrupt_submodule" bash -c '
  wrapper_src="$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/scripts/lib" "${tmpdir}/bin" "${tmpdir}/prompts"
  cp "${wrapper_src}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
  cat > "${tmpdir}/scripts/lib/prompts-submodule.sh" <<'"'"'EOF_HELPER'"'"'
#!/usr/bin/env bash
set -Eeuo pipefail
PS_CTX_KIND="${PS_CTX_KIND:-}"
PS_CTX_REPORT_PATH="${PS_CTX_REPORT_PATH:-}"
PS_CTX_REPO_ROOT="${PS_CTX_REPO_ROOT:-}"
PS_CTX_PROMPTS_PATH="${PS_CTX_PROMPTS_PATH:-}"
PS_CTX_STRICT_REMOTE="${PS_CTX_STRICT_REMOTE:-auto}"
PS_CTX_AUTO_UPDATE="${PS_CTX_AUTO_UPDATE:-false}"
ps_repo_root() { cd "$(dirname "$1")/.." && pwd; }
ps_ctx_init() { : "${PS_CTX_KIND:?}"; : "${PS_CTX_REPORT_PATH:?}"; }
ps_log_json() { :; }
ps_prompts_submodule_path() { printf "prompts\n"; }
ps_prompts_submodule_initialized() { return 0; }
ps_tracking_branch() { printf "main\n"; }
ps_git_fetch_remote_branch() { return 0; }
ps_should_strict_fail_remote() { return 1; }
ps_submodule_has_local_changes() { return 1; }
ps_finish_and_exit() {
  mkdir -p "$(dirname "${PS_CTX_REPORT_PATH}")"
  printf "{\"outcome\":\"%s\"}\n" "$1" > "${PS_CTX_REPORT_PATH}"
  exit "${3:-0}"
}
EOF_HELPER
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then
  exit 1
fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh" "${tmpdir}/bin/git"
  rc=0
  PATH="${tmpdir}/bin:${PATH}" SUBMODULE_REPORT_JSON="${tmpdir}/report.json" \
    bash "${tmpdir}/scripts/prompts-submodule-freshness.sh" >/dev/null 2>&1 || rc=$?
  [[ "${rc}" -eq 1 ]]
  python3 - <<PY
import json
from pathlib import Path
print(json.loads(Path(${tmpdir@Q} + "/report.json").read_text(encoding="utf-8"))["outcome"])
PY
' _ "${FRESHNESS_SCRIPT}"

th_assert_run "wrapper-skip-remote-unreachable" 0 "skip_remote_unreachable" bash -c '
  wrapper_src="$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/scripts/lib" "${tmpdir}/bin" "${tmpdir}/prompts"
  cp "${wrapper_src}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
  cat > "${tmpdir}/scripts/lib/prompts-submodule.sh" <<'"'"'EOF_HELPER'"'"'
#!/usr/bin/env bash
set -Eeuo pipefail
PS_CTX_KIND="${PS_CTX_KIND:-}"
PS_CTX_REPORT_PATH="${PS_CTX_REPORT_PATH:-}"
PS_CTX_REPO_ROOT="${PS_CTX_REPO_ROOT:-}"
PS_CTX_PROMPTS_PATH="${PS_CTX_PROMPTS_PATH:-}"
PS_CTX_STRICT_REMOTE="${PS_CTX_STRICT_REMOTE:-auto}"
ps_repo_root() { cd "$(dirname "$1")/.." && pwd; }
ps_ctx_init() { : "${PS_CTX_KIND:?}"; : "${PS_CTX_REPORT_PATH:?}"; }
ps_log_json() { :; }
ps_prompts_submodule_path() { printf "prompts\n"; }
ps_prompts_submodule_initialized() { return 0; }
ps_tracking_branch() { printf "main\n"; }
ps_git_fetch_remote_branch() { return 1; }
ps_should_strict_fail_remote() { return 1; }
ps_submodule_has_local_changes() { return 1; }
ps_finish_and_exit() {
  mkdir -p "$(dirname "${PS_CTX_REPORT_PATH}")"
  printf "{\"outcome\":\"%s\"}\n" "$1" > "${PS_CTX_REPORT_PATH}"
  exit "${3:-0}"
}
EOF_HELPER
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then
  printf "%s\n" deadbeef
  exit 0
fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh" "${tmpdir}/bin/git"
  PATH="${tmpdir}/bin:${PATH}" SUBMODULE_REPORT_JSON="${tmpdir}/report.json" \
    bash "${tmpdir}/scripts/prompts-submodule-freshness.sh" >/dev/null 2>&1
  python3 - <<PY
import json
from pathlib import Path
print(json.loads(Path(${tmpdir@Q} + "/report.json").read_text(encoding="utf-8"))["outcome"])
PY
' _ "${FRESHNESS_SCRIPT}"

th_assert_run "wrapper-worktree-only-update" 0 "pass_auto_updated_worktree_only" bash -c '
  wrapper_src="$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/scripts/lib" "${tmpdir}/bin" "${tmpdir}/prompts"
  cp "${wrapper_src}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
  cat > "${tmpdir}/scripts/lib/prompts-submodule.sh" <<'"'"'EOF_HELPER'"'"'
#!/usr/bin/env bash
set -Eeuo pipefail
PS_CTX_KIND="${PS_CTX_KIND:-}"
PS_CTX_REPORT_PATH="${PS_CTX_REPORT_PATH:-}"
PS_CTX_REPO_ROOT="${PS_CTX_REPO_ROOT:-}"
PS_CTX_PROMPTS_PATH="${PS_CTX_PROMPTS_PATH:-}"
PS_CTX_STRICT_REMOTE="${PS_CTX_STRICT_REMOTE:-auto}"
PS_CTX_AUTO_UPDATE="${PS_CTX_AUTO_UPDATE:-false}"
ps_repo_root() { cd "$(dirname "$1")/.." && pwd; }
ps_ctx_init() { : "${PS_CTX_KIND:?}"; : "${PS_CTX_REPORT_PATH:?}"; }
ps_log_json() { :; }
ps_prompts_submodule_path() { printf "prompts\n"; }
ps_prompts_submodule_initialized() { return 0; }
ps_tracking_branch() { printf "main\n"; }
ps_git_fetch_remote_branch() { return 0; }
ps_should_strict_fail_remote() { return 1; }
ps_submodule_has_local_changes() { return 1; }
ps_finish_and_exit() {
  mkdir -p "$(dirname "${PS_CTX_REPORT_PATH}")"
  printf "{\"outcome\":\"%s\"}\n" "$1" > "${PS_CTX_REPORT_PATH}"
  exit "${3:-0}"
}
EOF_HELPER
  cat > "${tmpdir}/bin/git" <<'"'"'EOF_GIT'"'"'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ "${args[*]}" == *" rev-parse HEAD"* ]]; then
  if [[ "${args[*]}" == *" checkout --detach "* ]]; then
    printf "%s\n" feedface
  else
    printf "%s\n" "${FAKE_HEAD_SHA:-deadbeef}"
  fi
  exit 0
fi
if [[ "${args[*]}" == *" rev-parse origin/main"* ]]; then
  printf "%s\n" feedface
  exit 0
fi
if [[ "${args[*]}" == *" submodule update --remote -- prompts"* ]]; then
  exit 1
fi
if [[ "${args[*]}" == *" checkout --detach "* ]]; then
  exit 0
fi
exit 0
EOF_GIT
  chmod +x "${tmpdir}/scripts/prompts-submodule-freshness.sh" "${tmpdir}/bin/git"
  PATH="${tmpdir}/bin:${PATH}" AUTO_UPDATE=true SUBMODULE_REPORT_JSON="${tmpdir}/report.json" \
    bash "${tmpdir}/scripts/prompts-submodule-freshness.sh" >/dev/null 2>&1
  python3 - <<PY
import json
from pathlib import Path
print(json.loads(Path(${tmpdir@Q} + "/report.json").read_text(encoding="utf-8"))["outcome"])
PY
' _ "${FRESHNESS_SCRIPT}"

th_assert_run "artifact-warning-does-not-mask-exit" 0 'artifact_warning' bash -c '
  source "$1"
  (
    PS_CTX_KIND=freshness PS_CTX_REPORT_PATH=/proc/eos-test/report.json PS_CTX_METRICS_PATH=/proc/eos-test/metrics.prom \
      PS_CTX_REPO_ROOT=/repo PS_CTX_PROMPTS_PATH=prompts PS_CTX_LOCAL_SHA=deadbeef \
      PS_CTX_REMOTE_SHA=feedface PS_CTX_REMOTE_BRANCH=main
    ps_ctx_init
    ps_finish_and_exit pass_up_to_date ok 0
  )
' _ "${HELPER_SCRIPT}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
mkdir -p "${tmpdir}/scripts/lib"
cp "${FRESHNESS_SCRIPT}" "${tmpdir}/scripts/prompts-submodule-freshness.sh"
cp "${HELPER_SCRIPT}" "${tmpdir}/scripts/lib/prompts-submodule.sh"
cp "${CI_COMMON_SCRIPT}" "${tmpdir}/scripts/lib/ci-common.sh"
cp "${GIT_ENV_SCRIPT}" "${tmpdir}/scripts/lib/git-env.sh"
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
