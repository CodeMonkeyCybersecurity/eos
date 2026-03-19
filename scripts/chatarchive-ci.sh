#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT_DIR"

OUT_DIR="$ROOT_DIR/outputs/chatarchive-ci"
mkdir -p "$OUT_DIR"

UNIT_COVERAGE_FILE="$OUT_DIR/unit.cover.out"
COMBINED_COVERAGE_FILE="$OUT_DIR/combined.cover.out"
SUMMARY_FILE="$OUT_DIR/summary.txt"

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

if [[ "${CHATARCHIVE_SKIP_E2E:-0}" != "1" ]]; then
  echo "==> E2E smoke tests"
  go test -tags=e2e_smoke ./test/e2e/smoke -run 'TestSmoke_(ChatArchive|BackupChats)' -count=1
else
  echo "==> E2E smoke tests skipped"
fi

node - "$UNIT_COVERAGE" "$COMBINED_COVERAGE" "$SUMMARY_FILE" <<'NODE'
const fs = require("node:fs");

const unit = Number(process.argv[2]);
const combined = Number(process.argv[3]);
const summaryPath = process.argv[4];

const summary = `Chat archive verification summary
Unit coverage: ${unit.toFixed(1)}%
Combined unit+integration coverage: ${combined.toFixed(1)}%
Test pyramid:
- Unit: go test ./pkg/chatarchive/...
- Integration: go test -tags=integration ./pkg/chatarchive/...
- E2E: go test -tags=e2e_smoke ./test/e2e/smoke -run TestSmoke_(ChatArchive|BackupChats)
`;

fs.writeFileSync(summaryPath, summary, "utf8");
process.stdout.write(summary);

if (unit < 70.0) {
  console.error(`Unit coverage ${unit.toFixed(1)}% is below the 70% floor.`);
  process.exit(1);
}
if (combined < 90.0) {
  console.error(`Combined coverage ${combined.toFixed(1)}% is below the 90% floor.`);
  process.exit(1);
}
NODE
