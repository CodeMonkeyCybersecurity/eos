# Security Code Review Checklist

**Last Updated**: 2025-01-27

Use this checklist for ALL code reviews involving:
- Secrets management
- Network operations (HTTP, TLS)
- Authentication/authorization
- File operations with sensitive data
- Vault cluster operations

---

## 🔐 Secrets Management

- [ ] Secrets retrieved via `secrets.SecretManager` (not hardcoded)
- [ ] Secrets never logged (even at DEBUG level)
- [ ] Secrets never passed in environment variables (use temp files with 0400 perms)
- [ ] Secrets not in struct JSON tags (implement `MarshalJSON()` to redact)
- [ ] Secrets cleared from memory after use (`defer` cleanup)
- [ ] Token files use `VAULT_TOKEN_FILE` instead of `VAULT_TOKEN` env var

**Reference**: P0-1 fix (`pkg/vault/cluster_token_security.go`)

---

## 🔒 TLS Configuration

- [ ] `InsecureSkipVerify = false` (or documented exception in `*_test.go`)
- [ ] Custom CA certificates loaded from standard paths
- [ ] TLS 1.2+ required (TLS 1.0/1.1 rejected)
- [ ] Certificate hostname verification enabled
- [ ] User consent required before disabling verification
- [ ] `VAULT_SKIP_VERIFY` only set with explicit user consent or `Eos_ALLOW_INSECURE_VAULT=true`

**Reference**: P0-2 fix (`pkg/vault/phase2_env_setup.go`)

**Standard CA Paths** (priority order):
1. `/etc/vault/tls/ca.crt`
2. `/etc/eos/ca.crt`
3. `/etc/ssl/certs/vault-ca.pem`

---

## 🌐 HTTP Clients

- [ ] Reuse existing service client (don't create new `http.Client` instances)
- [ ] Connection pooling configured
- [ ] Timeouts set (no infinite waits)
- [ ] Retry logic only for transient errors
- [ ] Rate limiting configured for external APIs
- [ ] Use `pkg/httpclient.NewClient()` for unified configuration

**Anti-Pattern**:
```go
// ❌ BAD: Creating new client per request
client := &http.Client{Transport: &http.Transport{...}}
```

**Correct Pattern**:
```go
// ✓ GOOD: Reuse shared client
client, err := httpclient.NewClient(config)
// Use client for all requests
```

---

## 🔑 Authentication & Authorization

- [ ] Token expiration validated before use
- [ ] Tokens stored with appropriate permissions (0400)
- [ ] Token cleanup on error paths (`defer`)
- [ ] Capability checks before privileged operations
- [ ] Audit logging for admin actions
- [ ] No tokens in logs (use `sanitizeTokenForLogging()`)

**Example**:
```go
tokenFile, err := createTemporaryTokenFile(rc, token)
if err != nil {
    return fmt.Errorf("failed to create token file: %w", err)
}
defer os.Remove(tokenFile.Name())  // ✓ Cleanup
```

---

## ⚠️ Error Handling

- [ ] Errors sanitized (no credential leakage)
- [ ] Connection strings redacted in errors
- [ ] Stack traces don't expose secrets
- [ ] User-facing errors provide remediation
- [ ] System errors logged with full context

**Example**:
```go
// ❌ BAD: Connection string with password in error
return fmt.Errorf("connection failed: %s", connString)

// ✓ GOOD: Redacted connection string
return fmt.Errorf("connection failed: %s", connStringRedacted)
```

---

## 📁 File Operations

- [ ] Permissions from constants (no hardcoded `0644`, `0755`)
- [ ] Atomic writes for config files
- [ ] Ownership set correctly (`vault:vault`, `consul:consul`)
- [ ] Temp files cleaned up (`defer os.Remove()`)
- [ ] Sensitive files have `0400`/`0600` permissions

**Required Documentation** (for each permission constant):
```go
// RATIONALE: Why this permission level
// SECURITY: What threats this mitigates
// THREAT MODEL: Attack scenarios prevented
const VaultConfigPerm = 0640
```

**Example**:
```go
// ❌ BAD: Hardcoded permission
os.Chmod(path, 0640)

// ✓ GOOD: Use constant
os.Chmod(path, vault.VaultConfigPerm)
```

---

## 🧪 Testing

- [ ] Security tests added for new functionality
- [ ] Negative tests (what happens with invalid input?)
- [ ] Boundary tests (token expiration, permission denied)
- [ ] Integration tests with real services (not mocks only)
- [ ] Tests verify secrets are NOT logged
- [ ] Tests verify cleanup happens (`defer` tested)

**Example Test**:
```go
func TestTokenNotInEnvironment(t *testing.T) {
    // Verify VAULT_TOKEN is NOT set
    if envToken := os.Getenv("VAULT_TOKEN"); envToken != "" {
        t.Errorf("Token leaked: %s", sanitize(envToken))
    }
}
```

---

## 📚 Documentation

- [ ] Security rationale documented (WHY this approach)
- [ ] Threat model considered (WHAT attacks does this prevent)
- [ ] Compliance requirements noted (PCI-DSS, SOC2, HIPAA)
- [ ] Remediation steps in error messages
- [ ] Examples show secure patterns

**Required Comments**:
```go
// SECURITY (P0-X FIX): <Brief description>
// RATIONALE: <Why this approach>
// THREAT MODEL: <What attacks prevented>
// COMPLIANCE: <Relevant standards>
```

---

## 🚨 Red Flags (Immediate Review Required)

### Critical Red Flags:
- ⛔ **Hardcoded secrets** (passwords, tokens, API keys)
- ⛔ **`VAULT_SKIP_VERIFY=1`** (unconditional)
- ⛔ **`InsecureSkipVerify=true`** (outside `*_test.go`)
- ⛔ **`VAULT_TOKEN` in env vars** (use `VAULT_TOKEN_FILE`)
- ⛔ **Secrets in logs** (even DEBUG level)

### High-Priority Red Flags:
- 🔴 **Multiple HTTP clients** for same service
- 🔴 **No connection pooling** (new client per request)
- 🔴 **Hardcoded file permissions** (not in `constants.go`)
- 🔴 **No token cleanup** (missing `defer os.Remove()`)
- 🔴 **Credentials in errors** (connection strings, passwords)

### Medium-Priority Red Flags:
- 🟡 **No retry logic** (network operations)
- 🟡 **No timeouts** (infinite waits)
- 🟡 **No capability checks** (privileged operations)
- 🟡 **Missing audit logs** (admin actions)
- 🟡 **Incomplete error context** (no remediation)

---

## ✅ Review Process

### Before Approving PR:
1. **Run pre-commit hook** locally: `.git/hooks/pre-commit`
2. **Check CI/CD pipeline**: All security checks must pass
3. **Manual review**: Use this checklist
4. **Test coverage**: Verify security tests exist
5. **Documentation**: Verify threat model documented

### Approval Criteria:
- ✅ All checklist items addressed
- ✅ Pre-commit hook passes
- ✅ CI/CD security workflow passes
- ✅ No critical red flags
- ✅ Security tests added
- ✅ Documentation complete

---

## 📋 Quick Reference

### Pre-Commit Hook Location:
```bash
.git/hooks/pre-commit
```

### CI/CD Workflow:
```bash
.github/workflows/security.yml
```

### Security Test Examples:
```bash
pkg/vault/cluster_token_security_test.go
```

### Security Fixes Reference:
- **P0-1**: Token exposure fix
- **P0-2**: VAULT_SKIP_VERIFY fix

---

## 🔗 Resources

- **CLAUDE.md**: Development standards and security rules
- **ROADMAP.md**: Security hardening sprint plan
- **P0-1_TOKEN_EXPOSURE_FIX_COMPLETE.md**: Token security guide
- **P0-2_VAULT_SKIP_VERIFY_FIX_COMPLETE.md**: TLS security guide

---

**Last Updated**: 2025-01-27  
**Maintainer**: Code Monkey Cybersecurity  
**Philosophy**: "Cybersecurity. With humans."
