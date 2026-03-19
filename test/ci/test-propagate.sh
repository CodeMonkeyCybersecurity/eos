#!/usr/bin/env bash
# Dispatcher for the propagation test pyramid (unit 70% / integration 20% / e2e 10%).
# CANONICAL guard: if prompts submodule is not initialized, all tiers skip here.
# Individual tier scripts do NOT need their own guards — this is the single check point.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=../../scripts/lib/git-env.sh
source "${REPO_ROOT}/scripts/lib/git-env.sh"
ge_unset_git_local_env

PROPAGATE_SCRIPT="${REPO_ROOT}/prompts/scripts/propagate.sh"

# --- Canonical submodule guard ---
# The prompts submodule requires authenticated access to cybermonkey/prompts.
# When the submodule is not initialized (CI auth issue, fresh clone without
# --recurse-submodules), skip ALL propagation tests gracefully.
# Durable fix: update the GITEA_TOKEN CI secret with read access to cybermonkey/prompts.
if [[ ! -f "${PROPAGATE_SCRIPT}" ]]; then
  echo "SKIP: prompts submodule not initialized — skipping entire propagation test pyramid"
  echo "  (${PROPAGATE_SCRIPT} not found)"
  echo "  To initialize locally: git submodule update --init prompts"
  echo "  CI durable fix: update GITEA_TOKEN secret with read access to cybermonkey/prompts"
  echo ""
  # Structured skip event for observability (consumed by report-alert.py)
  _ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")"
  echo "{\"ts\":\"${_ts}\",\"suite\":\"propagate\",\"status\":\"skip\",\"reason\":\"prompts_submodule_unavailable\",\"tiers_skipped\":[\"unit\",\"integration\",\"e2e\"]}" >&2
  echo "[unit] Results: 0 passed, 0 failed, 0 total (skipped)"
  echo "[integration] Results: 0 passed, 0 failed, 0 total (skipped)"
  echo "[e2e] Results: 0 passed, 0 failed, 0 total (skipped)"
  echo "[propagate] test pyramid complete (all tiers skipped — submodule unavailable)"
  exit 0
fi

echo "[propagate] unit (70%)"
bash "${SCRIPT_DIR}/test-propagate-unit.sh"

echo "[propagate] integration (20%)"
bash "${SCRIPT_DIR}/test-propagate-integration.sh"

echo "[propagate] e2e (10%)"
bash "${SCRIPT_DIR}/test-propagate-e2e.sh"

echo ""
echo "[propagate] test pyramid complete"
