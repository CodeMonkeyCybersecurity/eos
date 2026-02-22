#!/usr/bin/env bash
set -euo pipefail

lane="${1:-${CI_LANE:-unknown}}"
status="${2:-${CI_STATUS:-unknown}}"
coverage_file="${CI_COVERAGE_FILE:-coverage.out}"
log_dir="${CI_LOG_DIR:-outputs/ci}"
report_file="${CI_REPORT_FILE:-${log_dir}/report.json}"
md_file="${CI_SUMMARY_FILE:-${log_dir}/summary.md}"

mkdir -p "${log_dir}"

go run ./test/ci/tool summary "${lane}" "${status}" "${log_dir}" "${coverage_file}" "${report_file}" "${md_file}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "${md_file}" >> "${GITHUB_STEP_SUMMARY}"
else
  cat "${md_file}"
fi
