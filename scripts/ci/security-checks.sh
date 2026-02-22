#!/usr/bin/env bash
set -euo pipefail

# Custom security checks for patterns that static analysis tools miss.
# Uses grep (POSIX portable) instead of rg for runner compatibility.
# Lines containing "# nosec", "#nosec", or "// nosec" are excluded.

errors=0

check_violation() {
  local label="$1"
  local pattern="$2"
  local exclude_pattern="$3"
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "${tmp}" "${tmp}.filtered"' RETURN

  grep -rn --include='*.go' --exclude-dir=vendor "${pattern}" . > "${tmp}" 2>/dev/null || true

  # Always exclude test files, nosec annotations, and comment-only lines
  local base_exclude='_test\.go|# nosec|#nosec|// nosec|^\s*//'
  if [[ -n "${exclude_pattern}" ]]; then
    exclude_pattern="${base_exclude}|${exclude_pattern}"
  else
    exclude_pattern="${base_exclude}"
  fi

  grep -Ev "${exclude_pattern}" "${tmp}" > "${tmp}.filtered" 2>/dev/null || true
  mv "${tmp}.filtered" "${tmp}"

  if [[ -s "${tmp}" ]]; then
    echo "FAIL: ${label}"
    cat "${tmp}"
    errors=$((errors + 1))
  else
    echo "PASS: ${label}"
  fi
}

# Check 1: VAULT_SKIP_VERIFY=1 outside of vault infrastructure and known helpers
check_violation \
  "VAULT_SKIP_VERIFY=1 in non-vault production code" \
  "VAULT_SKIP_VERIFY.*1" \
  "handleTLSValidationFailure|Eos_ALLOW_INSECURE_VAULT|# P0-2|pkg/vault/|zap\.String"

# Check 2: InsecureSkipVerify=true outside of known internal-service packages.
# Excluded: vault, httpclient (TLS helper), wazuh/ldap/hecate (internal comms, tracked as tech debt)
check_violation \
  "InsecureSkipVerify=true in non-infrastructure code" \
  'InsecureSkipVerify.*true' \
  "pkg/httpclient/|pkg/vault/|pkg/wazuh/|pkg/ldap/|pkg/hecate/|# INSECURE|#nosec G402|SECURITY:"

# Check 3: VAULT_TOKEN string interpolation (token exposure)
check_violation \
  "VAULT_TOKEN interpolation exposure" \
  'fmt\.Sprintf.*VAULT_TOKEN.*%s' \
  "VAULT_TOKEN_FILE|# P0-1|pkg/debug/"

if [[ "${errors}" -gt 0 ]]; then
  echo ""
  echo "::error::Security validation failed with ${errors} issue(s)"
  echo "To suppress a known-safe finding, add '// nosec' or '#nosec' comment on the line."
  exit 1
fi

echo "All custom security checks passed"
