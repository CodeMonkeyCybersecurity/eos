#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

# shellcheck source=lib/lane-runtime.sh
source "${script_dir}/lib/lane-runtime.sh"
# shellcheck source=../lib/git-env.sh
source "${script_dir}/../lib/git-env.sh"

ensure_no_merge_conflicts() {
  local unmerged_files
  unmerged_files="$(git diff --name-only --diff-filter=U || true)"
  if [[ -n "${unmerged_files}" ]]; then
    echo "::error::Unmerged files detected:"
    echo "${unmerged_files}"
    return 1
  fi

  local conflict_markers
  conflict_markers="$(git grep -nE '^(<<<<<<< .+|=======$|>>>>>>> .+)$' -- . ':!vendor' || true)"
  if [[ -n "${conflict_markers}" ]]; then
    echo "::error::Merge conflict markers detected in tracked files:"
    echo "${conflict_markers}"
    return 1
  fi
}

cd "${repo_root}"
lane_init "debug" "${repo_root}"
lane_acquire_lock
trap 'lane_on_err "${LINENO}" "${BASH_COMMAND}"' ERR
lane_log "INFO" "ci_debug.start" "Starting ci:debug parity lane" "bootstrap"

lane_run_step "policy_validate" go run ./test/ci/tool policy-validate test/ci/suites.yaml
lane_run_step "preflight" scripts/ci/preflight.sh
lane_run_step "sanitize_git_env" ge_unset_git_local_env
lane_run_step "git_conflict_guard" ensure_no_merge_conflicts

export PATH="$(go env GOPATH)/bin:${PATH}"
if ! command -v golangci-lint >/dev/null 2>&1; then
  lane_log "INFO" "ci_debug.bootstrap" "golangci-lint missing; installing pinned v2.0.0" "bootstrap"
  lane_run_step "install_golangci_lint" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.0.0
fi

export CI_EVENT_NAME="${CI_EVENT_NAME:-pull_request}"
export CI_BASE_REF="${CI_BASE_REF:-main}"
if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" || -n "${GITEA_ACTIONS:-}" ]]; then
  lane_run_step "lint_changed" scripts/ci/lint.sh changed
else
  CI_LANE_STAGE="local_lint"
  changed_go_files="$(git diff --cached --name-only --diff-filter=ACMR -- '*.go' | grep -v '^vendor/' || true)"
  if [[ -z "${changed_go_files}" ]]; then
    changed_go_files="$(git diff --name-only --diff-filter=ACMR -- '*.go' | grep -v '^vendor/' || true)"
  fi

  if [[ -n "${changed_go_files}" ]]; then
    lane_log "INFO" "ci_debug.local_lint" "Running local changed-file lint" "local_lint"
    unformatted="$(echo "${changed_go_files}" | xargs -r gofmt -s -l)"
    if [[ -n "${unformatted}" ]]; then
      CI_LANE_FAILED_STAGE="local_lint"
      CI_LANE_FAILED_COMMAND="gofmt -s -l changed_go_files"
      CI_LANE_FAILED_LINE=0
      lane_finish "fail" "gofmt check failed for changed Go files" 1
    fi

    local_base="$(git merge-base HEAD "${CI_BASE_REF}" 2>/dev/null || git rev-parse "${CI_BASE_REF}" 2>/dev/null || echo "")"
    if [[ -n "${local_base}" ]]; then
      lane_run_step "lint_changed" golangci-lint run --timeout=8m --config=.golangci.yml --new-from-rev="${local_base}"
    else
      changed_pkgs="$(echo "${changed_go_files}" | xargs -n1 dirname | sort -u | sed 's|^|./|')"
      lane_run_step "lint_changed_fallback" bash -c 'echo "$1" | xargs -r golangci-lint run --timeout=8m --config=.golangci.yml' _ "${changed_pkgs}"
    fi
  else
    lane_log "INFO" "ci_debug.local_lint" "No changed Go files detected; skipping local lint" "local_lint"
  fi
fi

lane_run_step "compile_smoke" go test -run '^$' ./cmd/...
lane_run_step "submodule_freshness_pyramid" bash test/ci/test-submodule-freshness.sh
lane_run_step "governance_wrapper_tests" bash test/ci/test-governance-check.sh
lane_run_step "verify_parity_contract_tests" bash test/ci/test-verify-parity.sh

CI_LANE_FAILED_STAGE="none"
CI_LANE_FAILED_COMMAND=""
CI_LANE_FAILED_LINE=0
CI_LANE_FAILED_EXIT=0
CI_LANE_STAGE="complete"
lane_finish "pass" "ci:debug completed successfully" 0
