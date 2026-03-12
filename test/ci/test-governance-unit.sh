#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

GOV_SCRIPT="${REPO_ROOT}/scripts/check-governance.sh"
ENTRY_SCRIPT="${REPO_ROOT}/scripts/prompts-submodule.sh"
INSTALL_HOOK_SCRIPT="${REPO_ROOT}/scripts/install-git-hooks.sh"
PRE_COMMIT_SCRIPT="${REPO_ROOT}/scripts/hooks/pre-commit-ci-debug.sh"
HELPER_SCRIPT="${REPO_ROOT}/scripts/lib/prompts-submodule.sh"
CI_COMMON_SCRIPT="${REPO_ROOT}/scripts/lib/ci-common.sh"
GIT_ENV_SCRIPT="${REPO_ROOT}/scripts/lib/git-env.sh"
REPORT_ALERT_SCRIPT="${REPO_ROOT}/scripts/ci/report-alert.py"

# --- Syntax checks ---
th_assert_run "governance-script-syntax" 0 "" bash -n "${GOV_SCRIPT}"
th_assert_run "entry-script-syntax" 0 "" bash -n "${ENTRY_SCRIPT}"
th_assert_run "install-hook-script-syntax" 0 "" bash -n "${INSTALL_HOOK_SCRIPT}"
th_assert_run "pre-commit-script-syntax" 0 "" bash -n "${PRE_COMMIT_SCRIPT}"
th_assert_run "helper-script-syntax" 0 "" bash -n "${HELPER_SCRIPT}"
th_assert_run "ci-common-script-syntax" 0 "" bash -n "${CI_COMMON_SCRIPT}"
th_assert_run "git-env-script-syntax" 0 "" bash -n "${GIT_ENV_SCRIPT}"
th_assert_run "report-alert-syntax" 0 "" python3 -m py_compile "${REPORT_ALERT_SCRIPT}"

# --- ShellCheck lint (if available) ---
if command -v shellcheck >/dev/null 2>&1; then
  for script in "${GOV_SCRIPT}" "${ENTRY_SCRIPT}" "${INSTALL_HOOK_SCRIPT}" "${PRE_COMMIT_SCRIPT}"; do
    script_name="$(basename "${script}")"
    th_assert_run "shellcheck-${script_name}" 0 "" shellcheck -x -S warning "${script}"
  done
  for lib in "${HELPER_SCRIPT}" "${CI_COMMON_SCRIPT}" "${GIT_ENV_SCRIPT}"; do
    lib_name="$(basename "${lib}")"
    th_assert_run "shellcheck-${lib_name}" 0 "" shellcheck -x -S warning "${lib}"
  done
  for mod in "${REPO_ROOT}/scripts/lib/prompts-submodule/"*.sh; do
    mod_name="$(basename "${mod}")"
    th_assert_run "shellcheck-${mod_name}" 0 "" shellcheck -x -S warning "${mod}"
  done
else
  echo "SKIP: shellcheck not installed"
fi

# --- Governance skip on uninitialized submodule ---
tmpdir="$(th_create_fixture)"
trap 'rm -rf "${tmpdir}"' EXIT
cat > "${tmpdir}/.gitmodules" <<'EOF_GITMODULES'
[submodule "prompts"]
	path = prompts
	url = https://example.invalid/prompts.git
EOF_GITMODULES

th_assert_run "governance-skip-uninitialized" 0 '"outcome":"skip_uninitialized"' \
  env GOVERNANCE_REPORT_JSON="${tmpdir}/governance-report.json" bash "${tmpdir}/scripts/check-governance.sh"
th_assert_json_field "governance-skip-kind" "${tmpdir}/governance-report.json" "kind" "governance"
th_assert_json_field "governance-skip-action" "${tmpdir}/governance-report.json" "action" "governance"
th_assert_json_field "governance-skip-schema" "${tmpdir}/governance-report.json" "schema_version" "2"

# --- Hook installation ---
hook_tmpdir="$(th_create_fixture)"
trap 'rm -rf "${tmpdir}" "${hook_tmpdir}"' EXIT
git -C "${hook_tmpdir}" init -q

th_assert_run "install-hook-installs-wrapper" 0 "Hook matches source: true" \
  bash -c 'cd "$1" && bash scripts/install-git-hooks.sh' _ "${hook_tmpdir}"

th_assert_json_field "install-hook-report-outcome" "${hook_tmpdir}/outputs/ci/install-hook/report.json" "outcome" "pass_installed"

th_assert_run "pre-commit-no-staged-changes" 0 "No staged changes" \
  bash -c 'cd "$1" && bash scripts/hooks/pre-commit-ci-debug.sh' _ "${hook_tmpdir}"
th_assert_json_field "pre-commit-report-outcome" "${hook_tmpdir}/outputs/ci/pre-commit/report.json" "outcome" "pass_no_staged_changes"

# --- install-hook error: not a git repo ---
th_assert_run "install-hook-not-git" 1 "not in a git repository" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/scripts/hooks"
  echo "#!/usr/bin/env bash" > "${tmpdir}/scripts/hooks/pre-commit-ci-debug.sh"
  chmod +x "${tmpdir}/scripts/hooks/pre-commit-ci-debug.sh"
  ps_install_hook "${tmpdir}" 2>&1
' _ "${HELPER_SCRIPT}"
th_assert_run "install-hook-not-git-report" 0 "fail_not_git_repo" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  mkdir -p "${tmpdir}/scripts/hooks"
  echo "#!/usr/bin/env bash" > "${tmpdir}/scripts/hooks/pre-commit-ci-debug.sh"
  chmod +x "${tmpdir}/scripts/hooks/pre-commit-ci-debug.sh"
  (ps_install_hook "${tmpdir}") >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/outputs/ci/install-hook/report.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

# --- pre-commit with staged changes but no tools ---
th_assert_run "pre-commit-parity-missing" 0 "verify-parity.sh not found" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  git -C "${tmpdir}" config user.email "test@test.com"
  git -C "${tmpdir}" config user.name "Test"
  echo "test" > "${tmpdir}/file.txt"
  git -C "${tmpdir}" add file.txt
  # Create a minimal debug.sh that succeeds
  mkdir -p "${tmpdir}/scripts/ci"
  echo "#!/usr/bin/env bash" > "${tmpdir}/scripts/ci/debug.sh"
  chmod +x "${tmpdir}/scripts/ci/debug.sh"
  PS_CTX_KIND=hook PS_CTX_ACTION=pre-commit PS_CTX_REPORT_PATH="${tmpdir}/report.json" PS_CTX_REPO_ROOT="${tmpdir}"
  ps_ctx_init
  ps_run_pre_commit "${tmpdir}" 2>&1
' _ "${HELPER_SCRIPT}"
th_assert_run "pre-commit-parity-report" 0 "pass_ci_debug" bash -c '
  source "$1"
  tmpdir="$(mktemp -d)"
  trap "rm -rf \"${tmpdir}\"" EXIT
  git -C "${tmpdir}" init -q
  git -C "${tmpdir}" config user.email "test@test.com"
  git -C "${tmpdir}" config user.name "Test"
  echo "test" > "${tmpdir}/file.txt"
  git -C "${tmpdir}" add file.txt
  mkdir -p "${tmpdir}/scripts/ci"
  echo "#!/usr/bin/env bash" > "${tmpdir}/scripts/ci/debug.sh"
  chmod +x "${tmpdir}/scripts/ci/debug.sh"
  PRE_COMMIT_REPORT_JSON="${tmpdir}/pre-commit.json"
  PS_CTX_KIND=hook
  PS_CTX_ACTION=pre-commit
  PS_CTX_REPORT_PATH="${tmpdir}/pre-commit.json"
  PS_CTX_REPO_ROOT="${tmpdir}"
  ps_ctx_init
  (ps_run_pre_commit "${tmpdir}") >/dev/null 2>&1 || true
  python3 -c "import json; print(json.load(open(${tmpdir@Q}+\"/pre-commit.json\"))[\"outcome\"])"
' _ "${HELPER_SCRIPT}"

th_summary "governance-unit"
