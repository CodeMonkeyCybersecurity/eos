#!/usr/bin/env bash
set -euo pipefail

lane_dir="outputs/ci/debug"
mkdir -p "${lane_dir}"
report="${lane_dir}/report.json"

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "${value}"
}

now_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

log_json() {
  local level="${1:-INFO}"
  local event="${2:-event}"
  local message="${3:-}"
  printf '{"ts":"%s","level":"%s","event":"%s","message":"%s"}\n' \
    "$(now_utc)" "$(json_escape "${level}")" "$(json_escape "${event}")" "$(json_escape "${message}")"
}

finish() {
  local status="${1:?status required}"
  local message="${2:?message required}"
  local exit_code="${3:?exit code required}"

  local level="INFO"
  if [[ "${status}" != "pass" ]]; then
    level="ERROR"
  fi

  log_json "${level}" "ci_debug.finish" "${message}"

  cat > "${report}" <<JSON
{
  "ts": "$(json_escape "$(now_utc)")",
  "lane": "ci-debug",
  "status": "$(json_escape "${status}")",
  "exit_code": ${exit_code},
  "message": "$(json_escape "${message}")"
}
JSON

  exit "${exit_code}"
}

trap 'finish "fail" "ci:debug failed unexpectedly at line ${LINENO}" 1' ERR

log_json "INFO" "ci_debug.start" "Starting ci:debug parity lane"

go run ./test/ci/tool policy-validate test/ci/suites.yaml
scripts/ci/preflight.sh

if ! command -v golangci-lint >/dev/null 2>&1; then
  log_json "INFO" "ci_debug.bootstrap" "golangci-lint missing; installing pinned v2.0.0"
  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.0.0
  export PATH="$(go env GOPATH)/bin:${PATH}"
fi

export CI_EVENT_NAME="${CI_EVENT_NAME:-pull_request}"
export CI_BASE_REF="${CI_BASE_REF:-main}"
if [[ -n "${CI:-}" || -n "${GITHUB_ACTIONS:-}" || -n "${GITEA_ACTIONS:-}" ]]; then
  scripts/ci/lint.sh changed
else
  changed_go_files="$(git diff --name-only --diff-filter=ACMR -- '*.go' | grep -v '^vendor/' || true)"
  if [[ -n "${changed_go_files}" ]]; then
    log_json "INFO" "ci_debug.local_lint" "Running local changed-file lint"
    unformatted="$(echo "${changed_go_files}" | xargs -r gofmt -s -l)"
    if [[ -n "${unformatted}" ]]; then
      finish "fail" "gofmt check failed for changed Go files" 1
    fi
    # Use --new-from-rev to lint only new/changed code, matching CI lint.sh behaviour.
    # Passing individual files from multiple packages causes typechecking errors;
    # --new-from-rev avoids this by linting the whole repo but only reporting new issues.
    local_base="$(git merge-base HEAD "${CI_BASE_REF}" 2>/dev/null || git rev-parse "${CI_BASE_REF}" 2>/dev/null || echo "")"
    if [[ -n "${local_base}" ]]; then
      golangci-lint run --timeout=8m --config=.golangci.yml --new-from-rev="${local_base}"
    else
      # Fallback: lint changed package directories (may report pre-existing issues)
      changed_pkgs="$(echo "${changed_go_files}" | xargs -n1 dirname | sort -u | sed 's|^|./|')"
      echo "${changed_pkgs}" | xargs golangci-lint run --timeout=8m --config=.golangci.yml
    fi
  else
    log_json "INFO" "ci_debug.local_lint" "No changed Go files detected; skipping local lint"
  fi
fi

# Keep ci:debug deterministic and fast: compile smoke + targeted test pyramid
go test -run '^$' ./cmd/...
bash test/ci/test-submodule-freshness.sh
bash test/ci/test-governance-check.sh

finish "pass" "ci:debug completed successfully" 0
