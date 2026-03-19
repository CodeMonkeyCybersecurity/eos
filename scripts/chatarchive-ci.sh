#!/usr/bin/env bash
#
# Chat archive CI pipeline: unit + integration + race + e2e + coverage gates.
# Uses the same npm-backed entrypoint as the pre-commit hook to avoid drift.

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT_DIR"

OUT_DIR="$ROOT_DIR/outputs/chatarchive-ci"
mkdir -p "$OUT_DIR"

UNIT_COVERAGE_FILE="$OUT_DIR/unit.cover.out"
COMBINED_COVERAGE_FILE="$OUT_DIR/combined.cover.out"
SUMMARY_FILE="$OUT_DIR/summary.txt"
SUMMARY_JSON_FILE="$OUT_DIR/summary.json"

echo "==> Hook and script parity checks"
bash -n .github/hooks/pre-commit
bash -n .github/hooks/setup-hooks.sh
bash -n scripts/install-git-hooks.sh
grep -q "npm run ci" .github/hooks/pre-commit

echo "==> Unit tests"
go test ./pkg/chatarchive/... -coverprofile="$UNIT_COVERAGE_FILE" -covermode=atomic
UNIT_COVERAGE="$(go tool cover -func="$UNIT_COVERAGE_FILE" | awk '/total:/ {gsub("%","",$3); print $3}')"

echo "==> Integration tests"
go test -tags=integration ./pkg/chatarchive/... -coverprofile="$COMBINED_COVERAGE_FILE" -covermode=atomic
COMBINED_COVERAGE="$(go tool cover -func="$COMBINED_COVERAGE_FILE" | awk '/total:/ {gsub("%","",$3); print $3}')"

echo "==> Race detector"
go test -race ./pkg/chatarchive/...

echo "==> Command compile checks"
go test ./internal/chatarchivecmd/... ./cmd/create ./cmd/backup

echo "==> E2E smoke tests"
go test -tags=e2e_smoke ./test/e2e/smoke -run 'TestSmoke_(ChatArchive|BackupChats)' -count=1

SUMMARY="Chat archive verification summary
Unit coverage: ${UNIT_COVERAGE}%
Combined unit+integration coverage: ${COMBINED_COVERAGE}%
Test pyramid:
- Unit: go test ./pkg/chatarchive/...
- Integration: go test -tags=integration ./pkg/chatarchive/...
- E2E: go test -tags=e2e_smoke ./test/e2e/smoke -run TestSmoke_(ChatArchive|BackupChats)"

echo "$SUMMARY" | tee "$SUMMARY_FILE"
cat > "$SUMMARY_JSON_FILE" <<EOF
{
  "unit_coverage": ${UNIT_COVERAGE},
  "combined_coverage": ${COMBINED_COVERAGE},
  "e2e_enabled": true,
  "checks": {
    "unit": "passed",
    "integration": "passed",
    "race": "passed",
    "compile": "passed",
    "e2e": "passed",
    "hook_parity": "passed"
  }
}
EOF

check_threshold() {
  local actual="$1" threshold="$2" label="$3"
  if awk "BEGIN {exit !($actual < $threshold)}"; then
    echo "FAIL: $label coverage ${actual}% is below the ${threshold}% floor." >&2
    exit 1
  fi
}

check_threshold "$UNIT_COVERAGE" 70.0 "Unit"
check_threshold "$COMBINED_COVERAGE" 90.0 "Combined"
