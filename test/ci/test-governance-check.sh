#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[governance] unit (70%)"
bash "${SCRIPT_DIR}/test-governance-unit.sh"
echo "[governance] integration (20%)"
bash "${SCRIPT_DIR}/test-governance-integration.sh"
echo "[governance] e2e (10%)"
bash "${SCRIPT_DIR}/test-governance-e2e.sh"

echo ""
echo "[governance] test pyramid complete"
