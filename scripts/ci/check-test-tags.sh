#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

check_tag() {
  local path="$1"
  local expected="$2"

  if [[ ! -f "${path}" ]]; then
    echo "::error::Missing expected test file ${path}"
    return 1
  fi

  local actual
  actual="$(grep -m1 '^//go:build ' "${path}" | sed 's|^//go:build ||' || true)"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "::error::${path} must declare //go:build ${expected} (found '${actual:-missing}')"
    return 1
  fi
}

while IFS='|' read -r path tag; do
  check_tag "${path}" "${tag}"
done <<'EOF'
pkg/backup/client_integration_test.go|integration
pkg/backup/repository_resolution_integration_test.go|integration
pkg/xdg/credentials_test.go|credentialstore
test/integration_test.go|integration
test/integration_scenarios_test.go|integration
test/e2e/full/vault_lifecycle_full_test.go|e2e_full
test/e2e/smoke/backup_smoke_test.go|e2e_smoke
test/e2e/smoke/chatarchive_smoke_test.go|e2e_smoke
test/e2e/smoke/chatbackup_smoke_test.go|e2e_smoke
test/e2e/smoke/self/update_smoke_test.go|e2e_smoke
test/e2e/smoke/self_update_smoke_test.go|e2e_smoke
test/e2e/smoke/vault_smoke_test.go|e2e_smoke
EOF

echo "Test build tags verified"
