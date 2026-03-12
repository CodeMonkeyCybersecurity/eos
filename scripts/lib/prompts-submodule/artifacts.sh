#!/usr/bin/env bash
set -Eeuo pipefail

ps_log_level_for_outcome() {
  local outcome="${1:?outcome required}"
  case "$(ps_status_from_outcome "${outcome}")" in
    fail)
      printf 'ERROR'
      ;;
    skip)
      printf 'WARN'
      ;;
    *)
      printf 'INFO'
      ;;
  esac
}

ps_log_json() {
  local level="${1:-INFO}"
  local event="${2:-event}"
  local outcome="${3:-unknown}"
  local message="${4:-}"

  printf '{"ts":"%s","schema_version":"%s","run_id":"%s","level":"%s","kind":"%s","action":"%s","event":"%s","outcome":"%s","status":"%s","message":"%s"}\n' \
    "$(ci_now_utc)" \
    "$(ci_json_escape "$(ps_schema_version)")" \
    "$(ci_json_escape "${PS_CTX_RUN_ID:-unknown}")" \
    "$(ci_json_escape "${level}")" \
    "$(ci_json_escape "${PS_CTX_KIND:-unknown}")" \
    "$(ci_json_escape "${PS_CTX_ACTION:-unknown}")" \
    "$(ci_json_escape "${event}")" \
    "$(ci_json_escape "${outcome}")" \
    "$(ps_status_from_outcome "${outcome}")" \
    "$(ci_json_escape "${message}")"
}

ps_warn_artifact_failure() {
  local artifact_kind="${1:?artifact kind required}"
  local artifact_path="${2:-unknown}"
  local detail="${3:-unknown error}"

  PS_CTX_ARTIFACT_WARNINGS=$((PS_CTX_ARTIFACT_WARNINGS + 1))
  printf '{"ts":"%s","schema_version":"%s","run_id":"%s","level":"WARN","kind":"%s","action":"%s","event":"artifact_warning","artifact":"%s","path":"%s","message":"%s"}\n' \
    "$(ci_now_utc)" \
    "$(ci_json_escape "$(ps_schema_version)")" \
    "$(ci_json_escape "${PS_CTX_RUN_ID:-unknown}")" \
    "$(ci_json_escape "${PS_CTX_KIND:-unknown}")" \
    "$(ci_json_escape "${PS_CTX_ACTION:-unknown}")" \
    "$(ci_json_escape "${artifact_kind}")" \
    "$(ci_json_escape "${artifact_path}")" \
    "$(ci_json_escape "${detail}")" >&2
}

ps_write_atomic_file() {
  local target_path="${1:?target path required}"
  local tmp_path

  mkdir -p "$(dirname "${target_path}")" || return 1
  tmp_path="$(mktemp "${target_path}.tmp.XXXXXX")" || return 1
  cat > "${tmp_path}" || {
    rm -f "${tmp_path}"
    return 1
  }
  mv -f "${tmp_path}" "${target_path}" || {
    rm -f "${tmp_path}"
    return 1
  }
}

ps_write_json_report() {
  local report_path="${1:?report path required}"
  local outcome="${2:?outcome required}"
  local message="${3:-}"
  local exit_code="${4:-0}"

  if ! ps_ctx_require; then
    ps_warn_artifact_failure "report" "${report_path}" "context missing for report emission"
    return 1
  fi

  ps_write_atomic_file "${report_path}" <<JSON || {
{
  "ts": "$(ci_json_escape "$(ci_now_utc)")",
  "schema_version": "$(ci_json_escape "$(ps_schema_version)")",
  "run_id": "$(ci_json_escape "${PS_CTX_RUN_ID}")",
  "kind": "$(ci_json_escape "${PS_CTX_KIND}")",
  "action": "$(ci_json_escape "${PS_CTX_ACTION}")",
  "outcome": "$(ci_json_escape "${outcome}")",
  "status": "$(ci_json_escape "$(ps_status_from_outcome "${outcome}")")",
  "exit_code": ${exit_code},
  "repo_root": "$(ci_json_escape "${PS_CTX_REPO_ROOT}")",
  "prompts_path": "$(ci_json_escape "${PS_CTX_PROMPTS_PATH}")",
  "local_sha": "$(ci_json_escape "${PS_CTX_LOCAL_SHA}")",
  "remote_sha": "$(ci_json_escape "${PS_CTX_REMOTE_SHA}")",
  "remote_branch": "$(ci_json_escape "${PS_CTX_REMOTE_BRANCH}")",
  "strict_remote": "$(ci_json_escape "${PS_CTX_STRICT_REMOTE}")",
  "auto_update": "$(ci_json_escape "${PS_CTX_AUTO_UPDATE}")",
  "artifact_warnings": ${PS_CTX_ARTIFACT_WARNINGS},
  "message": "$(ci_json_escape "${message}")"
}
JSON
    ps_warn_artifact_failure "report" "${report_path}" "failed to write JSON report"
    return 1
  }
}

ps_emit_prom_metrics() {
  local outcome="${1:-unknown}"
  if [[ -z "${PS_CTX_METRICS_PATH:-}" ]]; then
    return 0
  fi

  local stale_value=0
  local status_value=0
  case "$(ps_status_from_outcome "${outcome}")" in
    pass)
      status_value=1
      ;;
    skip)
      status_value=0
      ;;
    fail)
      status_value=-1
      ;;
  esac
  if [[ "${outcome}" == "fail_stale" ]]; then
    stale_value=1
  fi

  ps_write_atomic_file "${PS_CTX_METRICS_PATH}" <<EOF_METRICS || {
# TYPE prompts_submodule_freshness_status gauge
prompts_submodule_freshness_status{outcome="${outcome}",strict_remote="${PS_CTX_STRICT_REMOTE}"} ${status_value}
# TYPE prompts_submodule_freshness_stale gauge
prompts_submodule_freshness_stale ${stale_value}
# TYPE prompts_submodule_freshness_last_run_timestamp_seconds gauge
prompts_submodule_freshness_last_run_timestamp_seconds $(ci_epoch)
EOF_METRICS
    ps_warn_artifact_failure "metrics" "${PS_CTX_METRICS_PATH}" "failed to write Prometheus textfile"
    return 1
  }
}

ps_finish_and_exit() {
  local outcome="${1:?outcome required}"
  local message="${2:?message required}"
  local exit_code="${3:?exit code required}"

  if ! ps_ctx_require; then
    printf 'FAIL: prompts-submodule context missing (kind/action/report_path)\n' >&2
    exit 1
  fi

  if ! ps_outcome_known "${PS_CTX_KIND}" "${outcome}"; then
    if [[ "${PS_CTX_KIND}" == "freshness" ]]; then
      outcome="fail_internal"
    else
      outcome="fail_checker_error"
    fi
    message="FAIL: internal error - unknown outcome emitted"
    exit_code=1
  fi

  local level event
  level="$(ps_log_level_for_outcome "${outcome}")"
  event="${PS_CTX_KIND}_check.finish"

  ps_log_json "${level}" "${event}" "${outcome}" "${message}"
  ps_write_json_report "${PS_CTX_REPORT_PATH}" "${outcome}" "${message}" "${exit_code}" || true

  if [[ "${PS_CTX_KIND}" == "freshness" ]]; then
    ps_emit_prom_metrics "${outcome}" || true
  fi

  exit "${exit_code}"
}

