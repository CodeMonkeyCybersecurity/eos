#!/usr/bin/env bash
set -euo pipefail

# Custom security checks for patterns static analysis can miss.
# Exclusions must be explicit and issue-tracked; avoid package-wide suppressions.

errors=0

check_violation() {
  local label="$1"
  local pattern="$2"
  local exclude_pattern="$3"
  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "${tmp}" "${tmp}.filtered"' RETURN

  grep -rn --include='*.go' --exclude-dir=vendor "${pattern}" . > "${tmp}" 2>/dev/null || true

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

# Check 1: VAULT_SKIP_VERIFY=1 should stay in vault lifecycle/setup-only code.
check_violation \
  "VAULT_SKIP_VERIFY=1 in non-vault production code" \
  "VAULT_SKIP_VERIFY.*1" \
  "handleTLSValidationFailure|Eos_ALLOW_INSECURE_VAULT|# P0-2|pkg/vault/|zap\.String"

# Check 2: InsecureSkipVerify=true with file-level temporary debt exceptions.
check_violation \
  "InsecureSkipVerify=true without explicit suppression" \
  'InsecureSkipVerify.*true' \
  "pkg/httpclient/tls_helper\.go|pkg/httpclient/migration\.go|pkg/httpclient/config\.go|pkg/vault/cert_renewal\.go|pkg/vault/phase8_health_check\.go|pkg/vault/phase2_env_setup\.go|pkg/ldap/handler\.go|pkg/wazuh/http_tls\.go|pkg/wazuh/agents/agent\.go|pkg/hecate/debug_bionicgpt\.go|pkg/hecate/add/wazuh\.go|# INSECURE|#nosec G402|SECURITY:"

# Check 3: VAULT_TOKEN string interpolation (token exposure)
check_violation \
  "VAULT_TOKEN interpolation exposure" \
  'fmt\.Sprintf.*VAULT_TOKEN.*%s' \
  "VAULT_TOKEN_FILE|# P0-1|pkg/debug/"

# Check gosec output against explicit allowlist (new findings fail).
if [[ -f outputs/ci/gosec.json ]]; then
  echo "Validating gosec findings against allowlist"
  if ! go run ./test/ci/tool gosec-check outputs/ci/gosec.json test/ci/security-allowlist.yaml; then
    errors=$((errors + 1))
  fi
fi

if [[ "${errors}" -gt 0 ]]; then
  echo ""
  echo "::error::Security validation failed with ${errors} issue(s)"
  echo "To suppress a known-safe finding, add '// nosec' or '#nosec' and link an issue."
  exit 1
fi

echo "All custom security checks passed"
