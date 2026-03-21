#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=lib/test-harness.sh
source "${SCRIPT_DIR}/lib/test-harness.sh"

HEALTH_SCRIPT="${REPO_ROOT}/scripts/monitor/chatbackup-health.sh"

th_assert_run "chatbackup-health-script-syntax" 0 "" bash -n "${HEALTH_SCRIPT}"

if ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: jq not installed"
  th_summary "chatbackup-health"
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

missing_status="${tmpdir}/missing.json"
th_assert_run "chatbackup-health-missing-status" 2 "status file not found" \
  bash "${HEALTH_SCRIPT}" "${missing_status}"

cat > "${tmpdir}/noop.json" <<'EOF_NOOP'
{
  "last_attempt": "2026-03-21T10:00:00Z",
  "last_run_state": "noop",
  "failure_count": 0,
  "users_scanned": ["henry"]
}
EOF_NOOP
th_assert_run "chatbackup-health-noop-warning" 1 "found no AI tool data yet" \
  bash "${HEALTH_SCRIPT}" "${tmpdir}/noop.json"

cat > "${tmpdir}/failure.json" <<'EOF_FAILURE'
{
  "last_attempt": "2026-03-21T10:00:00Z",
  "last_run_state": "failure",
  "last_failure": "2026-03-21T10:00:00Z",
  "last_error": "restic backup failed: repository locked",
  "failure_count": 3,
  "users_scanned": ["henry"],
  "tools_found": ["claude-code"]
}
EOF_FAILURE
th_assert_run "chatbackup-health-current-failure" 2 "latest backup run failed" \
  bash "${HEALTH_SCRIPT}" "${tmpdir}/failure.json"

cat > "${tmpdir}/recovered.json" <<'EOF_RECOVERED'
{
  "last_attempt": "2099-03-21T10:00:00Z",
  "last_run_state": "success",
  "last_success": "2099-03-21T10:00:00Z",
  "last_failure": "2099-03-20T10:00:00Z",
  "failure_count": 1,
  "success_count": 5,
  "users_scanned": ["henry"],
  "tools_found": ["claude-code"]
}
EOF_RECOVERED
th_assert_run "chatbackup-health-historical-failure-does-not-warn" 0 "state=success" \
  bash "${HEALTH_SCRIPT}" "${tmpdir}/recovered.json"

cat > "${tmpdir}/stale.json" <<'EOF_STALE'
{
  "last_attempt": "2020-03-21T10:00:00Z",
  "last_run_state": "success",
  "last_success": "2020-03-21T10:00:00Z",
  "success_count": 5
}
EOF_STALE
th_assert_run "chatbackup-health-stale-critical" 2 "threshold=24h" \
  bash "${HEALTH_SCRIPT}" "${tmpdir}/stale.json"

th_summary "chatbackup-health"
