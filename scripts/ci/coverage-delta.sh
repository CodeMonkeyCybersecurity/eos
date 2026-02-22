#!/usr/bin/env bash
set -euo pipefail

# Coverage delta gate: warns (non-blocking) when PR coverage drops below base.
# Runs base-branch tests in a temporary worktree. Skipped outside PR context.

coverage_file="${1:-coverage.out}"
ci_event="${CI_EVENT_NAME:-${GITHUB_EVENT_NAME:-}}"
base_ref="${CI_BASE_REF:-${GITHUB_BASE_REF:-}}"

if [[ "${ci_event}" != "pull_request" || -z "${base_ref}" ]]; then
  echo "Skipping coverage delta check (not a pull_request context)"
  exit 0
fi

if [[ ! -f "${coverage_file}" ]]; then
  echo "::warning::Coverage file not found: ${coverage_file}"
  exit 0
fi

git fetch origin "${base_ref}" --depth=1 >/dev/null 2>&1 || true
base_rev="$(git rev-parse "origin/${base_ref}" 2>/dev/null || true)"
if [[ -z "${base_rev}" ]]; then
  echo "::warning::Unable to resolve base revision for coverage delta"
  exit 0
fi

current_cov="$(go tool cover -func="${coverage_file}" | awk '/^total:/ {gsub("%","",$3); print $3}')"
if [[ -z "${current_cov}" ]]; then
  echo "::warning::Unable to parse current coverage"
  exit 0
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  git worktree remove --force "${tmp_dir}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

git worktree add --detach "${tmp_dir}" "${base_rev}" >/dev/null 2>&1

# Run base-branch tests with a timeout to prevent CI stalls.
# Failures on the base branch are not actionable in this PR, so treat as warning.
base_test_ok=true
if command -v timeout >/dev/null 2>&1; then
  timeout --signal=TERM --kill-after=15s 10m bash -c \
    "cd '${tmp_dir}' && go test -short -count=1 -vet=off -coverprofile=coverage.base.out -covermode=atomic ./pkg/... >/dev/null 2>&1" || base_test_ok=false
else
  (cd "${tmp_dir}" && go test -short -count=1 -vet=off -coverprofile=coverage.base.out -covermode=atomic ./pkg/... >/dev/null 2>&1) || base_test_ok=false
fi

if [[ "${base_test_ok}" != "true" ]]; then
  echo "::warning::Base branch tests failed or timed out — skipping coverage delta"
  exit 0
fi

base_cov="$(go tool cover -func="${tmp_dir}/coverage.base.out" | awk '/^total:/ {gsub("%","",$3); print $3}')"
if [[ -z "${base_cov}" ]]; then
  echo "::warning::Unable to parse base coverage"
  exit 0
fi

echo "Coverage delta check: base=${base_cov}% current=${current_cov}%"
awk -v base="${base_cov}" -v cur="${current_cov}" 'BEGIN { if (cur + 0.0001 < base) exit 1 }' || {
  echo "::warning::Coverage decreased: base=${base_cov}% current=${current_cov}% (non-blocking)"
  exit 0
}
