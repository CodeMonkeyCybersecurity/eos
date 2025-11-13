# Phase 1 Execution Guide - Security Critical Fixes (P0)

**Date Created**: 2025-11-13
**Status**: Ready for Execution (Pending Network Connectivity)
**Estimated Time**: 3-4 days
**Risk Level**: Low (Automated with backups)

---

## Executive Summary

This guide provides step-by-step instructions for executing **Phase 1** of the systematic remediation plan documented in ROADMAP.md "Adversarial Analysis & Systematic Remediation (2025-11-13)".

**What Phase 1 Fixes**:
- **P0-1**: Flag Bypass Vulnerability (357 commands unprotected, CVE-worthy)
- **P0-7**: InsecureSkipVerify TLS Issues (19 files requiring justification)
- **P0-5**: Documentation Policy Compliance (COMPLETED - 6 files consolidated)

**Deliverables**:
- All 357 commands protected with `ValidateNoFlagLikeArgs()`
- TLS security audit complete with justified exceptions
- CVE announcement: "Flag bypass vulnerability patched in eos v1.X"

---

## Prerequisites

### System Requirements
- Go 1.25.3+ installed and accessible
- Network connectivity to `storage.googleapis.com` (for Go toolchain download)
- Git configured with user identity
- Write access to eos repository

### Verification Commands
```bash
# Check Go version (should be 1.25.3+)
go version

# Check network connectivity
ping -c 1 storage.googleapis.com

# Check git identity
git config user.name && git config user.email

# Verify on correct branch
git branch --show-current
# Should be: claude/eos-adversarial-analysis-011CV4zCrddG5gJjzf9ySyom
```

### Current Blocker Status
**BLOCKER**: Network connectivity issue
```
Error: dial tcp: lookup storage.googleapis.com on [::1]:53: read udp [::1]:18896->[::1]:53: read: connection refused
```

**Resolution Required**: Fix DNS resolution or network routing to allow Go toolchain download

---

## Phase 1.1: Flag Bypass Vulnerability Fix (P0-1)

### Context

**Vulnerability**: Cobra's `--` separator allows bypassing flag-based safety checks.

**Attack Example**:
```bash
# User intends to use --force flag, but makes typo with '--' separator
sudo eos delete env production -- --force

# What Cobra parses:
# Args: ["production", "--force"]  ← Both are positional arguments!
# Flags: force=false               ← Flag NEVER parsed!

# Result: Production environment deleted without force confirmation
```

**Impact**: 357 of 363 commands (98.3%) are vulnerable to this attack.

### Execution Steps

#### Step 1: Preview Changes (Dry-Run)
```bash
cd /home/user/eos

# Preview what would be changed (safe, no modifications)
./scripts/add-flag-validation.sh --dry-run

# Expected output:
# - List of files to be modified
# - Import statements to be added
# - Validation code to be inserted
# - Summary: "Files modified: N, Files skipped: M"
```

**What to Look For**:
- Files listed should have `cobra.ExactArgs`, `cobra.MaximumNArgs`, or `cobra.MinimumNArgs`
- Already-protected files should be skipped (e.g., `cmd/delete/env.go`)
- Import additions should be `"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"`

#### Step 2: Apply Fixes (Production Run)
```bash
# SAFETY: Script creates .bak backups of all modified files
./scripts/add-flag-validation.sh

# Expected output:
# ✓ Added flag validation
# ✓ Added verify package import
# ...
# COMPLETE - Backup files created with .bak extension
```

**What Gets Modified**:
- **Import block**: Adds `"github.com/CodeMonkeyCybersecurity/eos/pkg/verify"` if missing
- **RunE function**: Inserts validation after `logger := otelzap.Ctx(rc.Ctx)`:
  ```go
  // CRITICAL: Detect flag-like args (P0-1 fix)
  if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
      return err
  }
  ```

#### Step 3: Verify Changes
```bash
# Review git diff (spot-check a few files)
git diff cmd/read/config.go | head -30
git diff cmd/backup/consul.go | head -30

# Should see:
# + import "github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
# + if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
```

#### Step 4: Build Validation
```bash
# CRITICAL: Must pass build before committing
go build -o /tmp/eos-build ./cmd/

# If build fails:
# 1. Review error messages carefully
# 2. Check for syntax errors in modified files
# 3. Restore from backups if needed: ls cmd/**/*.bak
```

#### Step 5: Test Validation Works
```bash
# Test that validation catches flag-like arguments
# This should FAIL with clear error message:
/tmp/eos-build delete env production -- --force

# Expected error:
# argument 1 looks like a long flag: '--force'
# Did you use the '--' separator by mistake?
# Remove the '--' separator to use flags properly.

# This should SUCCEED (correct usage):
/tmp/eos-build delete env production --force
```

#### Step 6: Commit Changes
```bash
git add cmd/

git commit -m "fix(security): protect 357 commands from flag bypass vulnerability (P0-1)

VULNERABILITY: CVE-worthy flag bypass via '--' separator
- Attack: 'eos delete env prod -- --force' bypasses --force flag check
- Impact: 357 commands (98.3%) were vulnerable
- Severity: High (production deletion, running VM deletion possible)

SOLUTION: Add ValidateNoFlagLikeArgs() to all commands with positional args
- Detects long flags (--flag), short flags (-f), distinguishes from negative numbers
- Clear error message with remediation steps
- Applied via automation script: scripts/add-flag-validation.sh

AUTOMATION:
- Script processed $(git diff --numstat | wc -l) files
- Automatic import of verify package where needed
- Backup files created (.bak extension) for safety

VALIDATION:
- Build passes: go build -o /tmp/eos-build ./cmd/
- Test attack blocked: eos delete env prod -- --force (now fails correctly)
- Test normal usage: eos delete env prod --force (still works)

REFERENCES:
- Analysis: ROADMAP.md 'Adversarial Analysis (2025-11-13) P0-1'
- Validation: pkg/verify/validators.go:ValidateNoFlagLikeArgs()
- Pattern: CLAUDE.md 'Flag Bypass Vulnerability Prevention'
"

git push
```

---

## Phase 1.2: InsecureSkipVerify TLS Audit (P0-7)

### Context

**Issue**: 19 files contain `InsecureSkipVerify: true`, which disables TLS certificate validation and enables man-in-the-middle attacks.

**Acceptable Use Cases**:
1. **Test files only** (`*_test.go`) - Self-signed certs in test environments
2. **Development mode** - Clearly marked with `if isDevelopment { ... }` check
3. **Explicit user consent** - Following P0-2 pattern (CA cert + informed consent)

**Unacceptable**: Production code with `InsecureSkipVerify: true` without justification

### Execution Steps

#### Step 1: Find All Instances
```bash
# List all files with InsecureSkipVerify
grep -rn "InsecureSkipVerify.*true" pkg/ cmd/ --include="*.go"

# Expected files (19 total):
# pkg/vault/cert_renewal.go
# pkg/vault/phase2_env_setup_integration_test.go
# pkg/vault/phase2_env_setup.go
# pkg/vault/phase6b_unseal.go
# pkg/vault/phase8_health_check.go
# pkg/wazuh/agents/agent.go
# pkg/wazuh/http_tls.go
# pkg/hecate/add/wazuh.go
# pkg/hecate/debug_bionicgpt.go
# pkg/httpclient/config.go
# pkg/httpclient/httpclient_test.go
# pkg/httpclient/migration.go
# pkg/httpclient/tls_helper.go
# pkg/ldap/handler.go
# (plus others)
```

#### Step 2: Categorize Each Instance
For each file, determine:
- **Test file?** (`*_test.go`) → Acceptable, add comment explaining why
- **Has dev mode check?** → Acceptable, verify check is correct
- **Production code?** → **REQUIRES FIX**

#### Step 3: Fix Production Code Violations

**Pattern 1: Add Dev/Prod Split**
```go
// BEFORE (INSECURE):
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,  // ← Dangerous!
}

// AFTER (SECURE):
func getTLSConfig(isDevelopment bool) *tls.Config {
    if isDevelopment {
        logger.Warn("Using InsecureSkipVerify for development",
            zap.String("reason", "self-signed certificates in dev environment"))
        return &tls.Config{InsecureSkipVerify: true}
    }

    // Production: proper certificate validation
    return &tls.Config{
        MinVersion: tls.VersionTLS12,
        // Certificate validation enabled (default)
    }
}
```

**Pattern 2: Use CA Certificate (Follow P0-2)**
```go
// Load CA certificate for validation
caPool, err := x509.SystemCertPool()
if err != nil {
    caPool = x509.NewCertPool()
}

// Add custom CA if needed
caCert, err := os.ReadFile("/etc/vault/tls/ca.crt")
if err == nil {
    caPool.AppendCertsFromPEM(caCert)
}

tlsConfig := &tls.Config{
    RootCAs:    caPool,
    MinVersion: tls.VersionTLS12,
    // InsecureSkipVerify: false (default)
}
```

**Pattern 3: Justify Test Usage**
```go
// In *_test.go files only:
// RATIONALE: Test environment uses self-signed certificates
// SECURITY: Test-only, never used in production
// THREAT MODEL: No production impact, isolated test environment
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,  // OK in tests
}
```

#### Step 4: Document Justifications
For each remaining `InsecureSkipVerify: true`, add inline comment:
```go
// SECURITY JUSTIFICATION (select one):
// - Test-only: Self-signed certificates in test environment
// - Dev-mode: Guarded by isDevelopment check
// - User consent: Following P0-2 informed consent pattern
```

#### Step 5: Validate
```bash
# Ensure no unjustified InsecureSkipVerify in production code
grep -rn "InsecureSkipVerify.*true" pkg/ cmd/ --include="*.go" \
    | grep -v "_test.go" \
    | grep -v "// SECURITY JUSTIFICATION"

# Should return empty (all justified)
```

#### Step 6: Commit
```bash
git add pkg/ cmd/

git commit -m "fix(security): audit and justify InsecureSkipVerify TLS bypasses (P0-7)

AUDIT COMPLETE: 19 instances of InsecureSkipVerify reviewed
- Test files: X instances (acceptable, documented)
- Dev mode: Y instances (guarded by isDevelopment check)
- Production: Z instances (FIXED or removed)

FIXES APPLIED:
- Added dev/prod split with runtime detection
- Implemented CA certificate validation for production
- Documented justifications for remaining test usage

SECURITY IMPACT:
- Before: 19 potential MitM attack vectors
- After: 0 unjustified TLS bypasses in production code
- All remaining instances documented with SECURITY JUSTIFICATION

VALIDATION:
- Build passes: go build -o /tmp/eos-build ./cmd/
- No unjustified InsecureSkipVerify in production code
- Test suite still passes: go test ./pkg/...

REFERENCES:
- Analysis: ROADMAP.md 'Adversarial Analysis (2025-11-13) P0-7'
- Pattern: P0-2 TLS Validation Fix (pkg/vault/phase2_env_setup.go)
- Standard: NIST 800-53 SC-8, SC-13
"

git push
```

---

## Phase 1.3: Final Validation & CVE Announcement

### Build & Test Validation
```bash
# Full build
go build -o /tmp/eos-build ./cmd/
if [ $? -ne 0 ]; then
    echo "BUILD FAILED - Fix errors before proceeding"
    exit 1
fi

# Run tests
go test -v ./pkg/verify/
go test -v ./pkg/shared/

# Lint check
golangci-lint run cmd/ pkg/

# All must pass before announcing CVE fix
```

### CVE Announcement (Draft)

```markdown
# Security Advisory: Flag Bypass Vulnerability in Eos CLI (CVE-2025-XXXX)

**Date**: 2025-11-XX
**Severity**: High (CVSS 7.8)
**Affected Versions**: eos v0.1.0 - v1.X.X
**Fixed Version**: eos v1.Y.0

## Vulnerability Summary

A vulnerability was discovered in the Eos CLI that allows bypassing flag-based safety checks through misuse of Cobra's `--` argument separator.

## Impact

An attacker or user making a command-line typo could bypass critical safety flags (e.g., `--force`, `--dry-run`, `--emergency-override`) leading to:
- Unintended production environment deletion
- Running VM forced termination without confirmation
- Emergency operations executed without proper authorization

**Attack Example**:
```bash
# User intends to use --force flag, types '--' separator by mistake
eos delete env production -- --force

# Result: Flag parsed as positional argument, not flag
# Effect: Production deleted without force confirmation
```

## Affected Commands

357 of 363 commands (98.3%) were vulnerable, including:
- Environment management: `eos delete env`
- VM operations: `eos delete kvm`
- Service operations: `eos update services`
- Configuration changes: `eos update vault`, `eos update consul`
- Emergency operations: `eos promote approve --emergency-override`

## Fix

All affected commands now include `ValidateNoFlagLikeArgs()` validation that detects and rejects flag-like positional arguments with clear error messages and remediation guidance.

**Fixed Behavior**:
```bash
$ eos delete env production -- --force
Error: argument 1 looks like a long flag: '--force'
Did you use the '--' separator by mistake?
Remove the '--' separator to use flags properly.
Example: Use 'eos delete env prod --force' instead
```

## Remediation

**For Users**:
1. Upgrade to eos v1.Y.0 or later: `eos self update`
2. Remove any usage of `--` separator in scripts
3. Use flags correctly: `eos command --flag` (not `eos command -- --flag`)

**For Developers**:
- Review ROADMAP.md "Adversarial Analysis (2025-11-13)"
- See CLAUDE.md "Flag Bypass Vulnerability Prevention" for pattern
- Reference implementation: pkg/verify/validators.go

## Credit

Discovered through comprehensive adversarial security analysis conducted 2025-11-13 using OWASP, NIST 800-53, CIS Benchmarks, and STRIDE threat modeling methodologies.

## References

- Vulnerability Analysis: ROADMAP.md
- Fix Implementation: PHASE1_EXECUTION_GUIDE.md
- Validation Function: pkg/verify/validators.go:ValidateNoFlagLikeArgs()
```

---

## Rollback Procedures

### If Build Fails After Flag Validation
```bash
# Restore all files from backups
for f in cmd/**/*.bak; do
    if [ -f "$f" ]; then
        mv "$f" "${f%.bak}"
        echo "Restored: ${f%.bak}"
    fi
done

# Verify restoration
go build -o /tmp/eos-build ./cmd/
```

### If Tests Fail After Changes
```bash
# Identify failing test
go test -v ./pkg/verify/ 2>&1 | grep FAIL

# Options:
# 1. Fix the test (if test is incorrect)
# 2. Fix the code (if implementation is incorrect)
# 3. Rollback and investigate (if unsure)
```

### If Production Issues Occur
```bash
# Emergency rollback
git revert HEAD  # Revert last commit
git push --force-with-lease

# Deploy previous version
sudo eos self update --version v1.X.Y  # Known good version
```

---

## Success Criteria

Phase 1 is complete when ALL of the following are true:

- [ ] Flag validation applied to 357 commands
- [ ] InsecureSkipVerify audit complete (19 files reviewed)
- [ ] All changes committed to git
- [ ] Build passes: `go build -o /tmp/eos-build ./cmd/`
- [ ] Tests pass: `go test -v ./pkg/verify/ ./pkg/shared/`
- [ ] Lint passes: `golangci-lint run`
- [ ] Attack test blocked: `eos delete env prod -- --force` fails with clear error
- [ ] Normal usage works: `eos delete env test --force` succeeds
- [ ] CVE announcement drafted and ready
- [ ] Changes pushed to remote branch

---

## Troubleshooting

### Issue: Script Hangs During Execution
**Symptom**: `./scripts/add-flag-validation.sh` runs but never completes

**Cause**: awk command processing may be slow on large files or have syntax issues

**Solution**:
```bash
# Run on subset of files first
for f in cmd/read/*.go; do
    ./scripts/add-flag-validation.sh --file "$f"
done

# If issue persists, manual application:
# 1. Add import: "github.com/CodeMonkeyCybersecurity/eos/pkg/verify"
# 2. Add validation after logger line:
#    if err := verify.ValidateNoFlagLikeArgs(args); err != nil {
#        return err
#    }
```

### Issue: Import Conflicts
**Symptom**: Build fails with "imported and not used" error for verify package

**Cause**: Import added but command doesn't have positional arguments

**Solution**:
```bash
# Remove unused import
goimports -w cmd/
```

### Issue: Network Still Unavailable
**Symptom**: Cannot download Go 1.25.3 toolchain

**Cause**: DNS resolution or network routing issue

**Solution**:
```bash
# Check DNS
nslookup storage.googleapis.com

# Try alternative DNS
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Or use pre-downloaded Go toolchain
# (contact system administrator)
```

---

## Time Estimates

**Phase 1.1 (Flag Validation)**:
- Preview: 5 minutes
- Apply: 10 minutes
- Verify: 15 minutes
- Test: 10 minutes
- Commit: 5 minutes
- **Total: ~45 minutes**

**Phase 1.2 (TLS Audit)**:
- Find instances: 10 minutes
- Categorize: 30 minutes (19 files × ~2 min each)
- Fix production code: 4-6 hours (depends on complexity)
- Document: 30 minutes
- Validate: 15 minutes
- Commit: 5 minutes
- **Total: ~6-8 hours**

**Phase 1.3 (CVE Announcement)**:
- Draft: 30 minutes
- Review: 15 minutes
- Publish: 15 minutes
- **Total: ~1 hour**

**TOTAL PHASE 1 TIME**: ~8-10 hours (1-1.5 days)

---

## Next Steps After Phase 1

Once Phase 1 is complete:
1. **Merge to main**: Create pull request with security fixes
2. **Tag release**: `git tag v1.Y.0` with CVE fix notes
3. **Announce**: Post security advisory to GitHub, docs, communication channels
4. **Begin Phase 2**: Compliance & Architecture fixes (hardcoded permissions, oversized cmd/ files)

See ROADMAP.md "Four-Phase Remediation Plan" for Phase 2+ details.

---

**Document Version**: 1.0
**Last Updated**: 2025-11-13
**Status**: Ready for Execution (Pending Network Connectivity)
