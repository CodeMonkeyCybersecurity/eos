#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
# shellcheck source=lib/lane-runtime.sh
source "${script_dir}/lib/lane-runtime.sh"

lane_init "self-update-quality" "${repo_root}"
lane_acquire_lock
trap 'lane_on_err "${LINENO}" "${BASH_COMMAND}"' ERR

coverage_file="${CI_LANE_DIR}/coverage.out"
focus_threshold="90"

unit_weight=70
integration_weight=20
e2e_weight=10

log_human() {
  local msg="${1:?message required}"
  echo "[${CI_LANE_NAME}] ${msg}"
  lane_log "INFO" "self_update_quality.message" "${msg}" "${CI_LANE_STAGE}"
}

require_test() {
  local pkg="${1:?pkg required}"
  local regex="${2:?regex required}"
  local label="${3:?label required}"
  shift 3

  local listed
  listed="$(go test "$@" -list "${regex}" "${pkg}" 2>/dev/null || true)"
  if ! grep -Eq "${regex}" <<< "${listed}"; then
    lane_log "ERROR" "self_update_quality.discovery.missing" "Required test missing: ${label}" "${CI_LANE_STAGE}"
    echo "[${CI_LANE_NAME}] ERROR: required test missing (${label})" >&2
    echo "[${CI_LANE_NAME}] Remediation: add/restore test matching /${regex}/ in ${pkg}" >&2
    return 1
  fi
  lane_log "INFO" "self_update_quality.discovery.found" "Required test discovered: ${label}" "${CI_LANE_STAGE}"
}

verify_tests_exist() {
  lane_run_step "test_discovery" require_test "./pkg/git" 'Test(IsTransientGitPullFailure|RunGitPullWithRetry_.*|RetryBackoff_.*|PullRepository_.*|PullLatestCode_FailsEarlyWithoutHTTPSCredentials)' "git retry/pull unit suite"
  lane_run_step "test_discovery" require_test "./pkg/self" 'Test(ShouldBuildBinary|RecordTransactionStep|CreateTransactionBackup_.*)' "self-update transaction unit suite"
  lane_run_step "test_discovery" require_test "./pkg/vault" 'TestHandleTLSValidationFailure_.*' "vault TLS consent unit suite"
  lane_run_step "test_discovery" require_test "./cmd/self" 'TestBackupRunCommandIntegration' "self backup integration test"
  lane_run_step "test_discovery" require_test "./pkg/git" 'Test(CheckRepositoryState_WithTrustedRemote|IntegrationPullWithStashTracking_PreservesUntrackedChanges)' "git trusted remote integration test"
  lane_run_step "test_discovery" require_test "./test/e2e/smoke" 'TestSmoke_SelfUpdateHelp' "self update e2e smoke test" -tags=e2e_smoke
}

run_unit() {
  log_human "running unit tests (${unit_weight}%)"
  go test -count=1 -short -coverprofile="${coverage_file}" -covermode=atomic \
    ./pkg/git ./pkg/self ./pkg/vault \
    -run 'Test(IsTransientGitPullFailure|RunGitPullWithRetry_.*|RetryBackoff_.*|VerifyTrustedRemote_.*|PullRepository_.*|PullLatestCode_FailsEarlyWithoutHTTPSCredentials|ShouldBuildBinary|RecordTransactionStep|CreateTransactionBackup_.*|HandleTLSValidationFailure_.*)'
}

run_integration() {
  log_human "running integration tests (${integration_weight}%)"
  go test -count=1 ./cmd/self -run 'TestBackupRunCommandIntegration'
  go test -count=1 -tags=integration ./pkg/git -run 'TestIntegrationPullWithStashTracking_PreservesUntrackedChanges'
}

run_e2e() {
  log_human "running e2e smoke tests (${e2e_weight}%)"
  go test -count=1 -tags=e2e_smoke ./test/e2e/smoke/...
}

compute_focus_coverage() {
  go tool cover -func="${coverage_file}" | awk '
    /PullRepository|runGitPullWithRetry|isTransientGitPullFailure|retryBackoff|handleTLSValidationFailure|shouldBuildBinary|recordTransactionStep|createTransactionBackup/ {
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
}

lane_log "INFO" "self_update_quality.start" "Starting self-update quality lane" "bootstrap"
verify_tests_exist
lane_run_step "unit" run_unit
lane_run_step "integration" run_integration
lane_run_step "e2e" run_e2e

focus_coverage="$(compute_focus_coverage)"
if [[ -z "${focus_coverage}" ]]; then
  lane_log "ERROR" "self_update_quality.coverage.parse_failed" "Failed to parse focused coverage from ${coverage_file}" "coverage_gate"
  echo "[${CI_LANE_NAME}] ERROR: failed to parse focused coverage from ${coverage_file}" >&2
  echo "[${CI_LANE_NAME}] Remediation: update the function-name pattern in compute_focus_coverage()" >&2
  false
fi

CI_LANE_STAGE="coverage_gate"
log_human "focused coverage=${focus_coverage}% threshold=${focus_threshold}%"
awk -v cov="${focus_coverage}" -v min="${focus_threshold}" 'BEGIN { if (cov+0 < min+0) exit 1 }' || {
  lane_log "ERROR" "self_update_quality.coverage.below_threshold" "Focused coverage ${focus_coverage}% below ${focus_threshold}%" "${CI_LANE_STAGE}"
  echo "[${CI_LANE_NAME}] ERROR: focused coverage ${focus_coverage}% below threshold ${focus_threshold}%" >&2
  false
}

export CI_LANE_EXTRA_METRICS="# TYPE eos_self_update_quality_coverage_percent gauge
eos_self_update_quality_coverage_percent ${focus_coverage}
# TYPE eos_self_update_quality_threshold_percent gauge
eos_self_update_quality_threshold_percent ${focus_threshold}
# TYPE eos_self_update_quality_unit_weight gauge
eos_self_update_quality_unit_weight ${unit_weight}
# TYPE eos_self_update_quality_integration_weight gauge
eos_self_update_quality_integration_weight ${integration_weight}
# TYPE eos_self_update_quality_e2e_weight gauge
eos_self_update_quality_e2e_weight ${e2e_weight}"

export CI_LANE_EXTRA_REPORT_FIELDS="coverage_percent=${focus_coverage}
coverage_threshold=#int:${focus_threshold}
weight_unit=#int:${unit_weight}
weight_integration=#int:${integration_weight}
weight_e2e=#int:${e2e_weight}"

lane_log "INFO" "self_update_quality.complete" "Self-update quality lane completed" "complete"
CI_LANE_STAGE="complete"
lane_finish "pass" "self-update quality lane completed successfully" 0
