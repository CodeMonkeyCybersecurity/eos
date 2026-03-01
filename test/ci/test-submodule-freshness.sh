#!/usr/bin/env bash
# Aggregate test runner for submodule freshness pyramid.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[submodule-freshness] unit (70%)"
bash "${SCRIPT_DIR}/test-submodule-freshness-unit.sh"
echo "[submodule-freshness] integration (20%)"
bash "${SCRIPT_DIR}/test-submodule-freshness-integration.sh"
echo "[submodule-freshness] e2e (10%)"
bash "${SCRIPT_DIR}/test-submodule-freshness-e2e.sh"

echo ""
echo "[submodule-freshness] test pyramid complete"
