#!/usr/bin/env bash
set -euo pipefail

lane="self-update-quality"
lane_dir="outputs/ci/${lane}"
mkdir -p "${lane_dir}"

report="${lane_dir}/report.json"
metrics="${lane_dir}/metrics.prom"
coverage_file="${lane_dir}/coverage.out"

log() {
  echo "[${lane}] $*"
}

# --- Test discovery: verify expected tests exist before running ---
verify_tests_exist() {
  local missing=0

  # Unit tests (pkg/git)
  local git_tests
  git_tests="$(go test -list 'TestIsTransientGitPullFailure|TestRunGitPullWithRetry' ./pkg/git 2>/dev/null || true)"
  if [[ -z "${git_tests}" ]]; then
    log "ERROR: expected unit tests not found in pkg/git"
    missing=1
  fi

  # Unit tests (pkg/vault)
  local vault_tests
  vault_tests="$(go test -list 'TestHandleTLSValidationFailure' ./pkg/vault 2>/dev/null || true)"
  if [[ -z "${vault_tests}" ]]; then
    log "ERROR: expected unit tests not found in pkg/vault"
    missing=1
  fi

  if [[ "${missing}" -ne 0 ]]; then
    log "FATAL: required tests missing - lane cannot produce valid results"
    exit 1
  fi

  log "test discovery OK"
}

run_unit() {
  log "running unit tests (70%)"
  go test -count=1 -short -coverprofile="${coverage_file}" -covermode=atomic \
    ./pkg/git ./pkg/vault \
    -run 'TestIsTransientGitPullFailure|TestRunGitPullWithRetry_.*|TestRetryBackoff_.*|TestVerifyTrustedRemote_.*|TestHandleTLSValidationFailure_.*'
}

run_integration() {
  log "running integration tests (20%)"
  # Use -list to verify tests exist, then run them. Skip gracefully if missing.
  if go test -list 'TestBackupRunCommandIntegration' ./cmd/self 2>/dev/null | grep -q 'TestBackup'; then
    go test -count=1 ./cmd/self -run 'TestBackupRunCommandIntegration'
  else
    log "WARN: TestBackupRunCommandIntegration not found in cmd/self, skipping"
  fi
  if go test -list 'TestCheckRepositoryState_WithTrustedRemote' ./pkg/git 2>/dev/null | grep -q 'TestCheck'; then
    go test -count=1 ./pkg/git -run 'TestCheckRepositoryState_WithTrustedRemote'
  else
    log "WARN: TestCheckRepositoryState_WithTrustedRemote not found in pkg/git, skipping"
  fi
}

run_e2e() {
  log "running e2e smoke tests (10%)"
  go test -count=1 -tags=e2e_smoke ./test/e2e/smoke/self/...
}

verify_tests_exist
run_unit
run_integration
run_e2e

# Coverage gate: compute focused coverage for critical retry/consent functions.
# Uses go tool cover output which lists per-function coverage percentages.
# The AWK pattern matches the function names we care about.
focus_coverage="$(
  go tool cover -func="${coverage_file}" | awk '
    /runGitPullWithRetry|isTransientGitPullFailure|retryBackoff|handleTLSValidationFailure/ {
      gsub("%","",$3); total += $3; count += 1
    }
    END {
      if (count == 0) {
        print ""
      } else {
        printf "%.2f", total / count
      }
    }
  '
)"
threshold="90"

if [[ -z "${focus_coverage}" ]]; then
  log "ERROR: failed to parse focused coverage from ${coverage_file}"
  log "This usually means the tracked functions were renamed."
  log "Update the AWK pattern in this script to match current function names."
  exit 1
fi

log "focused coverage=${focus_coverage}% threshold=${threshold}%"
awk -v cov="${focus_coverage}" -v min="${threshold}" 'BEGIN { if (cov+0 < min+0) exit 1 }' || {
  log "ERROR: focused coverage ${focus_coverage}% is below threshold ${threshold}%"
  exit 1
}

# Weights rationale:
# - Unit (70%): Fast, focused coverage of critical retry/consent paths
# - Integration (20%): Realistic scenarios with actual git/command interactions
# - E2E (10%): Smoke-level validation that CLI wiring works end-to-end
cat > "${metrics}" <<EOF
# TYPE eos_self_update_quality_coverage_percent gauge
eos_self_update_quality_coverage_percent ${focus_coverage}
# TYPE eos_self_update_quality_threshold_percent gauge
eos_self_update_quality_threshold_percent ${threshold}
# TYPE eos_self_update_quality_unit_weight gauge
eos_self_update_quality_unit_weight 70
# TYPE eos_self_update_quality_integration_weight gauge
eos_self_update_quality_integration_weight 20
# TYPE eos_self_update_quality_e2e_weight gauge
eos_self_update_quality_e2e_weight 10
EOF

cat > "${report}" <<EOF
{
  "lane": "${lane}",
  "status": "pass",
  "coverage_percent": ${focus_coverage},
  "coverage_threshold": ${threshold},
  "weights": {
    "unit": 70,
    "integration": 20,
    "e2e": 10
  }
}
EOF

log "completed"
