#!/usr/bin/env bash
set -euo pipefail

lane="${1:-${CI_LANE:-unknown}}"
status="${2:-${CI_STATUS:-unknown}}"
coverage_file="${CI_COVERAGE_FILE:-coverage.out}"
log_dir="${CI_LOG_DIR:-outputs/ci}"

pass_count=0
fail_count=0
skip_count=0

if compgen -G "${log_dir}/*.jsonl" >/dev/null 2>&1; then
  pass_count="$(grep -ch '"Action":"pass"' "${log_dir}"/*.jsonl 2>/dev/null | awk '{s+=$1} END {print s+0}')"
  fail_count="$(grep -ch '"Action":"fail"' "${log_dir}"/*.jsonl 2>/dev/null | awk '{s+=$1} END {print s+0}')"
  skip_count="$(grep -ch '"Action":"skip"' "${log_dir}"/*.jsonl 2>/dev/null | awk '{s+=$1} END {print s+0}')"
fi

flake_count=0
if compgen -G "${log_dir}/*" >/dev/null 2>&1; then
  flake_count="$(grep -RihcE 'flaky|flake' "${log_dir}" 2>/dev/null | awk '{s+=$1} END {print s+0}')"
fi

coverage="N/A"
if [[ -f "${coverage_file}" ]]; then
  coverage="$(go tool cover -func="${coverage_file}" 2>/dev/null | awk '/^total:/ {print $3}')" || true
fi

summary="### CI Lane Summary: ${lane}

- Status: ${status}
- Test events: pass=${pass_count}, fail=${fail_count}, skip=${skip_count}
- Coverage: ${coverage}
- Flake signatures: ${flake_count}
"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  echo "${summary}" >> "${GITHUB_STEP_SUMMARY}"
else
  echo "${summary}"
fi
