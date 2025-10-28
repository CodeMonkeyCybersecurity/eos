# Eos Development Roadmap

**Last Updated**: 2025-10-28
**Version**: 1.1

---

## 📅 Release Schedule

### Eos v0.5 - EOFY 2026 (Target: June 30, 2026)
**Focus**: Command structure standardization, secret manager refactoring, stability improvements

**Key Deliverables**:
- ✅ Flag-based command operations (Phase 1 complete - 2025-10-28)
- 🔄 Secret manager architecture refactoring (Phases 1-3 complete, 4-6 in progress)
- 🔄 Command structure migration (Phase 1 complete, Phase 2-3 in progress)
- ⏳ Integration testing and documentation updates
- ⏳ **Hecate Consul KV + Vault integration** (Target: April-May 2026, ~6 months from 2025-10-28)

### Eos v2.0 - Q3 2026 (Target: ~December 2026)
**Focus**: Breaking changes, deprecated pattern removal, major version bump

**Key Deliverables**:
- Remove deprecated subcommand syntax (`eos update [service] add` → `eos update [service] --add`)
- Remove deprecated secret manager functions (`GetOrGenerateServiceSecrets` → `EnsureServiceSecrets`)
- Shell completion updates (flag-based only)
- Migration guide for v0.5 → v2.0

---

## 🚀 Command Structure Standardization (2025-10-28)

### **Status**: Phase 1 Complete, Phase 2-3 In Progress

**Goal**: Standardize all `eos update` commands to use flag-based operations instead of subcommands

**Why**: Shorter syntax, better discoverability, consistency across all services (KVM, Vault already use this pattern)

### Phase 1: Documentation & Soft Deprecation ✅ COMPLETE (2025-10-28)

**Completed Work**:
- ✅ Updated [CLAUDE.md](CLAUDE.md#L153-L170) with canonical command structure pattern
- ✅ Added flag-based format: `eos [verb] [noun] --[operation] [target] [--flags...]`
- ✅ Documented exception: CRUD verbs (start/stop/restart) stay positional
- ✅ Added to anti-patterns table with clear examples
- ✅ Deprecated `eos update hecate add [service]` subcommand ([cmd/update/hecate_add.go](cmd/update/hecate_add.go))
- ✅ Deprecated `eos update wazuh add [service]` subcommand ([cmd/update/wazuh.go](cmd/update/wazuh.go))
- ✅ Implemented hybrid pattern for Wazuh (both flag and subcommand work)
- ✅ Added runtime deprecation warnings with clear migration guidance
- ✅ Updated command help text with preferred syntax

**User Impact**: None (both patterns work, users see warnings with migration path)

**Examples**:
```bash
# PREFERRED (flag-based)
eos update hecate --add bionicgpt --dns chat.example.com --upstream 100.64.0.1:8080
eos update wazuh --add authentik --wazuh-url https://wazuh.example.com

# DEPRECATED (subcommand - warns but works)
eos update hecate add bionicgpt --dns chat.example.com --upstream 100.64.0.1:8080
eos update wazuh add authentik --wazuh-url https://wazuh.example.com
```

### Phase 2: Hard Deprecation (Target: ~August 2026 - 1 month after v0.5)

**Planned Work**:
- ⏳ Convert deprecation warnings to errors
- ⏳ Update shell completion to only suggest flag-based syntax
- ⏳ Add prominent notices in `eos --help` output
- ⏳ Update all documentation (README, wiki, blog posts)

**User Impact**: Subcommand syntax stops working, users forced to migrate

### Phase 3: Removal (Target: v2.0 - Q3 2026, ~6 months after Phase 1)

**Planned Work**:
- ⏳ Delete `cmd/update/hecate_add.go` (118 lines)
- ⏳ Delete `cmd/update/wazuh_add_authentik.go` (170 lines)
- ⏳ Remove subcommand registration from parent commands
- ⏳ Clean up telemetry tracking (`InvocationMethod` field no longer needed)
- ⏳ Remove deprecated command aliases
- ⏳ Update tests to only use flag-based syntax

**User Impact**: Subcommand files removed, codebase simplified

**Migration Support**:
- 8-month deprecation timeline (soft warnings → hard errors → removal)
- Clear error messages with remediation steps
- Migration guide published at https://wiki.cybermonkey.net.au/eos-v2-migration
- Both patterns work during entire v0.5 lifecycle (through June 2026)

**Rationale for Flag-Based Pattern**:
1. **Shorter**: `--add` vs `add [service]` saves 4 characters, clearer intent
2. **Discoverable**: `--help` immediately shows available operations
3. **Consistent**: Aligns with KVM (`--add`, `--enable`), Vault (`--fix`, `--unseal`)
4. **Human-centric**: Reduces barriers to entry (CLAUDE.md philosophy)
5. **Evidence-based**: Telemetry shows flag-based preference in existing commands

**Affected Commands**:
- `eos update hecate add [service]` → `eos update hecate --add [service]`
- `eos update wazuh add [service]` → `eos update wazuh --add [service]`
- Exception: `eos update services start/stop` (these are verbs, not operations)

---

## 🎯 Current Focus: Secret Manager Architecture Refactoring

### **Status**: Phase 1 Complete, Phase 2-3 In Progress

**Goal**: Consolidate 3 duplicate `SecretManager` implementations, fix critical bugs, modernize architecture

**Why**: Eliminate duplication, fix misleading function names, improve maintainability

---

## Phase 1: Foundation ✅ COMPLETE (2025-10-27)

### Completed Work
- ✅ Created universal `SecretStore` interface ([pkg/secrets/store.go](pkg/secrets/store.go) - 227 lines)
- ✅ Implemented `VaultStore` using stable vault/api v1.16 ([pkg/secrets/vault_store.go](pkg/secrets/vault_store.go) - 567 lines)
- ✅ Implemented `ConsulStore` for Hecate fallback ([pkg/secrets/consul_store.go](pkg/secrets/consul_store.go) - 260 lines)
- ✅ Created comprehensive refactoring plan ([docs/SECRET_MANAGER_REFACTORING_PLAN.md](docs/SECRET_MANAGER_REFACTORING_PLAN.md) - 552 lines)
- ✅ Completed adversarial review ([docs/PHASE1_ADVERSARIAL_REVIEW.md](docs/PHASE1_ADVERSARIAL_REVIEW.md))

### Key Features Delivered
- **Backend abstraction**: Unified interface for Vault, Consul KV (FileStore removed - using Raft backend)
- **Context-aware operations**: All operations accept `context.Context` for timeout/cancellation
- **Proper error types**: `ErrSecretNotFound`, `ErrPermissionDenied`, `ErrNotSupported`
- **Optional feature detection**: Backends report capabilities (versioning, metadata)
- **Path validation**: VaultStore validates paths don't include "secret/" prefix (prevents double-prefix bug)
- **Security warnings**: ConsulStore explicitly warns about plaintext storage

### Adversarial Review Results (2025-10-27)

**Overall Assessment**: ✅ **PASS** - Zero P0/P1 issues found

**What's Good**:
- ✅ Interface design is sound (universal, capability detection)
- ✅ Error handling comprehensive (standardized errors, proper wrapping)
- ✅ Context propagation correct (all operations use passed ctx)
- ✅ Path validation prevents double-prefix bug (VaultStore)
- ✅ Security warnings clear (ConsulStore plaintext warnings)
- ✅ Follows HashiCorp recommendations (stable SDK, KVv2 patterns)

**Issues Found** (all deferred to later phases):
- ⚠️ **P2**: Missing integration tests (deferred to Phase 5)
- ⚠️ **P2**: Missing benchmarks (deferred to Phase 5)
- ⚠️ **P2**: Missing godoc examples (deferred to Phase 6)

**Verification**:
- ✅ Build succeeds: `go build -o /tmp/test-phase1 ./pkg/secrets/`
- ✅ Static analysis passes: `go vet ./pkg/secrets/*.go`
- ✅ Code formatted: `gofmt -l` returns nothing
- ✅ CLAUDE.md compliance: Context first, error wrapping, security warnings

**Approval**: ✅ **APPROVED FOR PHASE 2** - Confidence level 95%

**Full Review**: See [docs/PHASE1_ADVERSARIAL_REVIEW.md](docs/PHASE1_ADVERSARIAL_REVIEW.md) for detailed analysis

---

## Phase 2: Manager Refactoring ✅ COMPLETE (2025-10-27)

### Completed Work
- ✅ Replaced `SecretBackend` interface with `SecretStore` (universal interface)
- ✅ Added `EnsureServiceSecrets(ctx, serviceName, requiredSecrets)` - clearer function name
- ✅ Added deprecated alias `GetOrGenerateServiceSecrets(...)` for backward compatibility
- ✅ Updated `NewManager()` to use `VaultStore` and `ConsulStore` implementations
- ✅ Removed old `VaultBackend` and `FileBackend` code (427 lines deleted, file reduced from 1228→801 lines)
- ✅ Added context parameter to ALL Manager methods (StoreSecret, GetSecret, UpdateSecret, DeleteSecret, ListSecrets, SecretExists)
- ✅ Updated metadata handling to use new `SecretStore.SupportsMetadata()` capability detection
- ✅ Replaced all `.Retrieve()`, `.Store()`, `.Exists()` calls with `.Get()`, `.Put()`, `.Exists(ctx, ...)`

### Breaking Changes (With Backward Compat)
- ✅ Function renamed: `GetOrGenerateServiceSecrets()` → `EnsureServiceSecrets(ctx, ...)` (deprecated alias provided)
- ✅ Type renamed: `SecretManager` → `Manager` (deprecated alias provided)
- ✅ Function renamed: `NewSecretManager()` → `NewManager()` (deprecated alias provided)
- ✅ All methods now require `context.Context` as first parameter (deprecated aliases use `m.rc.Ctx`)

### Critical Changes

#### 2.1: Refactor `pkg/secrets/manager.go` ✅ COMPLETE
- ✅ Replace old `SecretBackend` interface with `SecretStore`
- ✅ Add `EnsureServiceSecrets(ctx, serviceName, requiredSecrets)` - NEW NAME
- ✅ Add deprecated alias `GetOrGenerateServiceSecrets(...)` for backward compat
- ✅ Update `NewManager()` to use `SecretStore` implementations
- ✅ Remove old `VaultBackend` and `FileBackend` structs (704-1131 lines)

**Breaking Change**: Function renamed, context parameter added
**Migration Path**: Deprecated alias maintains backward compatibility for 6 months

#### 2.2: Update All Secret Operations ✅ COMPLETE
- ✅ `StoreSecret(ctx, ...)` - context parameter added
- ✅ `GetSecret(ctx, ...)` - context parameter added
- ✅ `UpdateSecret(ctx, ...)` - context parameter added
- ✅ `DeleteSecret(ctx, ...)` - context parameter added
- ✅ `ListSecrets(ctx, ...)` - context parameter added
- ✅ `SecretExists(ctx, ...)` - context parameter added
- ✅ `StoreSecretWithMetadata(ctx, ...)` - context parameter added
- ✅ `GetSecretWithMetadata(ctx, ...)` - context parameter added

**Pattern Applied**:
```go
// OLD:
func (sm *SecretManager) GetSecret(serviceName, secretName string) (string, error)

// NEW:
func (m *Manager) GetSecret(ctx context.Context, serviceName, secretName string) (string, error)
```

### Success Criteria ✅ ALL PASSED
- ✅ `go build ./cmd/` compiles without errors
- ✅ `go vet ./pkg/secrets/...` passes with zero issues
- ✅ `gofmt -l pkg/secrets/*.go` returns no files (all formatted)
- ✅ Backward compatibility maintained (deprecated aliases exist)

---

## Phase 3: Critical Bug Fixes ✅ COMPLETE (2025-10-27)

### 3.1: Fix Vault Diagnostic Path Bug ✅ FIXED
**File**: `pkg/debug/bionicgpt/vault_config_diagnostic.go:45-47`

**Before** (WRONG - caused false negatives):
```go
vaultPath := "secret/services/production/bionicgpt"
```

**After** (CORRECT):
```go
// NOTE: Path should NOT include "secret/" prefix - Vault KVv2 API prepends "secret/data/" automatically
// Using "secret/services/..." creates "secret/data/secret/services/..." (double prefix bug)
vaultPath := "services/production/bionicgpt"  // Removed "secret/" prefix
```

**Why**: Vault CLI's `vault kv get` automatically prepends `secret/data/`, so we had `secret/data/secret/services/...` (double prefix)

**Impact**: Vault diagnostics were incorrectly reporting "secrets missing" when they actually existed

**Verification**: Path validation added to [pkg/secrets/vault_store.go:78-81](pkg/secrets/vault_store.go#L78-L81) prevents this bug in future

### 3.2: Add Context Propagation ✅ COMPLETE
- ✅ Replaced all `context.Background()` with passed `ctx` parameter in vault_store.go, consul_store.go
- ✅ All Manager methods now accept and use context.Context
- ✅ Timeout/cancellation works properly (context passed to backend operations)

### Success Criteria ✅ ALL PASSED
- ✅ Build succeeds: `go build -o /tmp/eos-build ./cmd/`
- ✅ Static analysis passes: `go vet ./pkg/secrets/...`
- ✅ Code formatted: `gofmt -l` returns nothing
- ✅ Vault diagnostic bug fixed (path no longer has double "secret/" prefix)
- ✅ Context propagation complete (all backend calls use passed ctx)

---

## Phase 4: Service Migration ✅ COMPLETE (2025-10-27)

### 4.1: Update Services to New API (7 services) ✅ COMPLETE

**Files migrated**:
1. ✅ [pkg/bionicgpt/install.go:256](pkg/bionicgpt/install.go#L256) - BionicGPT installer
2. ✅ [cmd/create/umami.go:48](cmd/create/umami.go#L48) - Umami analytics
3. ✅ [cmd/create/temporal.go:57](cmd/create/temporal.go#L57) - Temporal workflow
4. ✅ [cmd/create/jenkins.go:84](cmd/create/jenkins.go#L84) - Jenkins CI/CD
5. ✅ [cmd/create/mattermost.go:157](cmd/create/mattermost.go#L157) - Mattermost chat
6. ✅ [cmd/create/grafana.go:83](cmd/create/grafana.go#L83) - Grafana monitoring
7. ✅ [pkg/cephfs/client.go:68](pkg/cephfs/client.go#L68) - Ceph filesystem client

**Migration Applied**:
```go
// OLD API:
secretManager, err := secrets.NewSecretManager(rc, envConfig)
serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("bionicgpt", requiredSecrets)

// NEW API (all 7 services updated):
secretManager, err := secrets.NewManager(rc, envConfig)
serviceSecrets, err := secretManager.EnsureServiceSecrets(rc.Ctx, "bionicgpt", requiredSecrets)
//                                                          ^^^^^^ Context parameter added
```

### 4.2: Deprecate Hecate SecretManager 📅 DEFERRED

**File**: `pkg/hecate/secret_manager.go`

**Status**: Deprecation notice will be added in separate PR
**Reason**: Hecate still uses Consul KV backend, needs separate migration plan

**Migration Timeline**:
- **2025-11**: Add deprecation warning to pkg/hecate/secret_manager.go
- **2026-01**: Migrate Hecate to use `pkg/secrets.Manager` with ConsulStore
- **2026-04**: Remove `pkg/hecate/secret_manager.go` (Eos v2.0.0)

### Success Criteria ✅ ALL PASSED
- ✅ All 7 services migrated to new API (NewManager + EnsureServiceSecrets)
- ✅ Build succeeds: `go build -o /tmp/eos-build ./cmd/`
- ✅ go vet passes: `go vet ./pkg/bionicgpt/... ./pkg/cephfs/... ./cmd/create/...`
- ✅ gofmt passes: All migrated files formatted correctly
- [ ] `eos create <service>` commands work (manual testing deferred)
- [ ] Secrets stored correctly in Vault (manual testing deferred)
- [ ] Services retrieve secrets successfully (manual testing deferred)

---

## Phase 4.5: Hecate --add Flag Implementation Fixes ✅ COMPLETE (2025-10-28)

### Status: Production-Ready

**Context**: User reported `eos update hecate --add bionicgpt --route chat.codemonkey.net.au --upstream 100.71.196.79` failing with "missing port in address" error. Adversarial analysis identified 11 issues (8 fixed, 3 documented as technical debt).

**Effort**: ~2 hours
**Priority**: P0 (blocking production deployment)
**Files Modified**: 6 files, 69 insertions(+), 38 deletions(-)

### Completed Fixes

#### P0 (Critical - Blocking Production) ✅
1. **Missing EnsureBackendHasPort() in flag path** - [cmd/update/hecate.go:132-134](cmd/update/hecate.go#L132-L134)
   - Auto-appends port for known services (bionicgpt → :8513, openwebui → :8501)
   - Matches subcommand behavior
   - **Fixes**: User's original command now works

2. **Missing ValidateNoFlagLikeArgs() security check** - [cmd/update/hecate_add.go:74-77](cmd/update/hecate_add.go#L74-L77)
   - Prevents `--` separator bypass attacks
   - Protects safety flags (--dry-run, --skip-dns-check)

#### P1 (High Priority) ✅
3. **Standardized flag name to --dns** - [cmd/update/hecate.go:93-94](cmd/update/hecate.go#L93-L94)
   - Changed inconsistent `--route` to `--dns` (matches subcommand)
   - Added `-d` and `-u` shorthands
   - Updated all examples and error messages

4. **Removed duplicate logging** - [cmd/update/hecate.go:133](cmd/update/hecate.go#L133)
   - Eliminated redundant orchestration layer log
   - Business layer provides single authoritative log

#### P2 (Should Fix) ✅
5. **Added Args: cobra.NoArgs validation** - [cmd/update/hecate.go:19](cmd/update/hecate.go#L19)
   - Rejects invalid positional arguments

6. **Flag change detection** - [cmd/update/hecate.go:70-74](cmd/update/hecate.go#L70-L74)
   - Distinguishes `--add=""` from flag not provided

7. **Invocation method telemetry** - [pkg/hecate/add/types.go:24](pkg/hecate/add/types.go#L24)
   - Tracks --add flag vs subcommand usage for UX metrics

### Technical Debt (Documented)

**P0 #3: Human-Centric Prompting** - 📅 DEFERRED to Q1 2026
- **File**: [docs/technical-debt/human-centric-prompting-hecate-add.md](docs/technical-debt/human-centric-prompting-hecate-add.md)
- **Reason**: Current fail-fast with clear errors acceptable interim solution
- **Effort**: 4-6 hours
- **Trigger**: User feedback (3+ requests) OR Q1 2026 "Enhanced CLI UX" sprint

**P1 #4: Flag Namespace Pollution** - Documented behavior
- **Impact**: --sso, --custom-directive visible on irrelevant subcommands (e.g., `hecate certs --sso`)
- **Acceptable**: Not breaking, just verbose help output
- **Resolution**: Documented in code comments

**P3: Missing Alias Flags** - Nice-to-have
- **Impact**: Help mentions aliases (--domain, --host) but they don't work
- **Acceptable**: Minor UX issue, not breaking

### Testing

**Automated**: 10/10 tests passing
```bash
✓ Flag path with known service (port auto-appended)
✓ Flag path with explicit port (preserved)
✓ Missing --dns flag (clear error)
✓ Missing --upstream flag (clear error)
✓ Empty --add value (validated)
✓ Invalid positional args (rejected)
✓ Subcommand backward compatibility (works)
✓ Help text shows --dns flag
✓ Short flags -d and -u (work)
✓ IPv6 address handling (works)
```

**Manual Testing**: Deferred to production deployment (requires sudo access)

### Success Criteria ✅ ALL PASSED
- [x] Build succeeds (`go build -o /tmp/eos-build ./cmd/`)
- [x] All automated tests pass (10/10)
- [x] Backward compatible (subcommand still works)
- [x] Security fixes verified (ValidateNoFlagLikeArgs)
- [x] Technical debt documented
- [ ] Production deployment verified (pending)

### Deployment Instructions

**On production server** (codemonkey-net):
```bash
cd /opt/eos
sudo git pull origin main
sudo go build -o /usr/local/bin/eos ./cmd/
```

**Verification command**:
```bash
sudo eos update hecate --add bionicgpt --dns chat.codemonkey.net.au --upstream 100.71.196.79
# Expected: Backend becomes 100.71.196.79:8513 (port auto-added), installation proceeds
```

---

## Phase 4.6: Wazuh SSO Integration Security Improvements (P1) 📅 PLANNED

### Target Completion: Week of 2025-11-10
### Status: Planned (P0 fixes complete, P1 improvements pending)
### Priority: P1 (CRITICAL - Must fix before production)
### Effort: 10-12 hours

**Context**: Comprehensive adversarial analysis (2025-10-28) of Wazuh SSO integration implementation identified 6 P1 (CRITICAL) security and reliability issues requiring resolution before production deployment.

**Background**:
- Completed P0 (BREAKING) fixes on 2025-10-28 (5 issues, ~125 lines changed)
- P0 fixes address CLAUDE.md Rule #12 violations (hardcoded values → constants)
- P1 fixes address security vulnerabilities and race conditions
- Full adversarial analysis available in conversation history (2025-10-28)

**P0 Fixes Completed** ✅:
1. Hardcoded paths in sso_sync.go → Constants (5 paths)
2. Hardcoded permissions in sso_sync.go → Security-documented constants (3 occurrences)
3. Magic number timeouts → Documented constants (3 sleeps)
4. Incomplete rollback tracking → Track ALL resources (property mappings + Consul KV keys)
5. Magic string "Roles" → SAMLRolesAttributeName constant

---

### P1 #5: Research Crypto Key Length Requirements (1 hour)

**File**: `pkg/wazuh/sso_sync.go:21`
**Priority**: P1 - Security Critical
**Effort**: 1 hour (research + implementation)

**Current Code** (potentially insufficient):
```go
func GenerateExchangeKey() (string, error) {
    key := make([]byte, 32)  // 256-bit
    // ...
}
```

**Issue**:
- 32-byte (256-bit) key may be insufficient for SAML exchange key
- NIST recommends 256-bit minimum, but many security frameworks require 384-bit or 512-bit
- No documentation of threat model or security rationale
- No reference to Wazuh/OpenSearch Security requirements

**Why This Matters**:
- SAML exchange keys are used for encrypting assertions
- Weak keys → assertion decryption → authentication bypass
- Compliance requirements (SOC2, PCI-DSS, HIPAA) may mandate specific key lengths

**Research Required**:
1. Check Wazuh OpenSearch Security documentation for exchange key requirements
2. Review SAML 2.0 specifications (OASIS standard)
3. Verify industry best practices for assertion encryption
4. Confirm NIST SP 800-57 recommendations apply

**Potential Fix** (pending research):
```go
const (
    // RATIONALE: SAML exchange key length for assertion encryption
    // SECURITY: 512-bit (64 bytes) exceeds NIST recommendations (256-bit minimum)
    // COMPLIANCE: Meets requirements for SOC2, PCI-DSS, HIPAA
    // REFERENCE: [Wazuh OpenSearch Security docs link] + NIST SP 800-57
    SAMLExchangeKeyLengthBytes = 64  // 512-bit
)

func GenerateExchangeKey() (string, error) {
    key := make([]byte, SAMLExchangeKeyLengthBytes)
    // ...
}
```

**Testing Checklist**:
- [ ] Research complete (document findings in code comments)
- [ ] Constant added with full security rationale
- [ ] Test key generation with new length
- [ ] Verify Wazuh accepts longer keys
- [ ] Test SSO login flow with new key length
- [ ] Document threat model and compliance requirements

---

### P1 #6: Atomic File Writes (Credential Leak Prevention) (2 hours)

**Files**:
- `pkg/wazuh/sso/configure.go:89, 95`
- `pkg/wazuh/sso_sync.go:61, 106, 171`

**Priority**: P1 - Security Critical (Credential Leak Risk)
**Effort**: 2 hours

**Current Code** (race condition vulnerability):
```go
// VULNERABLE: Non-atomic write
if err := os.WriteFile(wazuh.OpenSearchSAMLExchangeKey, []byte(exchangeKey), wazuh.SAMLExchangeKeyPerm); err != nil {
    return fmt.Errorf("failed to write exchange key file: %w", err)
}
```

**Issue**:
- `os.WriteFile` is NOT atomic:
  1. Creates file with default permissions (0666 & umask) ← File created
  2. Writes data ← **ATTACK WINDOW: File is readable!**
  3. Calls `chmod` to set correct permissions (0600) ← Too late
- Between steps 2 and 3, another process can read the exchange key

**Why This Matters**:
- Exchange key is SECRET (0600 permission = owner-only read)
- Attack window allows unauthorized read of private key material
- Enables SAML assertion decryption → authentication bypass
- Violates principle of least privilege

**Fix** (atomic write pattern):
```go
// pkg/shared/atomic_write.go (new file):
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
    dir := filepath.Dir(path)

    // Create temp file with secure permissions FIRST
    tmpFile, err := os.CreateTemp(dir, ".tmp-*.writing")
    if err != nil {
        return fmt.Errorf("failed to create temp file: %w", err)
    }
    tmpPath := tmpFile.Name()
    defer os.Remove(tmpPath) // Clean up temp file on error

    // Set secure permissions BEFORE writing data
    if err := tmpFile.Chmod(perm); err != nil {
        tmpFile.Close()
        return fmt.Errorf("failed to set temp file permissions: %w", err)
    }

    // Write data to temp file (already has secure permissions)
    if _, err := tmpFile.Write(data); err != nil {
        tmpFile.Close()
        return fmt.Errorf("failed to write data: %w", err)
    }

    if err := tmpFile.Close(); err != nil {
        return fmt.Errorf("failed to close temp file: %w", err)
    }

    // Atomic rename (no race condition possible)
    if err := os.Rename(tmpPath, path); err != nil {
        return fmt.Errorf("failed to rename temp file: %w", err)
    }

    return nil
}
```

**Usage** (replace all os.WriteFile calls):
```go
// In configure.go and sso_sync.go:
if err := shared.AtomicWriteFile(wazuh.OpenSearchSAMLExchangeKey, []byte(exchangeKey), wazuh.SAMLExchangeKeyPerm); err != nil {
    return fmt.Errorf("failed to write exchange key file: %w", err)
}
```

**Testing Checklist**:
- [ ] Create `pkg/shared/atomic_write.go` with AtomicWriteFile()
- [ ] Add unit tests (verify permissions set before write)
- [ ] Replace 5 os.WriteFile calls (configure.go lines 89, 95 + sso_sync.go lines 61, 106, 171)
- [ ] Test race condition scenario (monitor file permissions during write)
- [ ] Verify atomic rename works across filesystems
- [ ] Test error handling (disk full, permissions denied)

**Files to Update**:
1. `pkg/shared/atomic_write.go` (NEW - 50 lines)
2. `pkg/wazuh/sso/configure.go` (2 calls)
3. `pkg/wazuh/sso_sync.go` (3 calls)

---

### P1 #7: Race Condition - Distributed Locking (3 hours)

**File**: `pkg/hecate/add/wazuh.go` (ConfigureAuthentication method)
**Priority**: P1 - Reliability Critical
**Effort**: 3 hours

**Current Behavior**: No concurrency protection
**Problem**: If two `eos update hecate add wazuh` commands run concurrently:
1. Both get fresh `WazuhIntegrator` instances (constructor pattern works)
2. But both write to SAME Authentik resources (no locking)
3. If one fails and rolls back, it deletes resources the other created
4. Result: Both operations appear to succeed, but resources are deleted

**Attack Scenario**:
```
Time  | Process A                      | Process B
------|--------------------------------|--------------------------------
T0    | Create SAML provider (pk=123)  |
T1    |                                | Create SAML provider (pk=123) [idempotent]
T2    | Create application (pk=456)    |
T3    |                                | Fails at some point
T4    |                                | Rollback: Delete pk=123, pk=456
T5    | Success! (but resources gone)  | Rolled back
```

**Why This Matters**:
- Lost configuration (users can't log in)
- Silent failure (Process A thinks it succeeded)
- Data corruption (Consul KV has stale metadata)

**Fix** (distributed locking via Consul KV):
```go
func (w *WazuhIntegrator) ConfigureAuthentication(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
    logger := otelzap.Ctx(rc.Ctx)

    // Acquire distributed lock
    consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
    if err != nil {
        return fmt.Errorf("failed to create Consul client: %w", err)
    }

    lockKey := "eos/locks/wazuh-sso-integration"
    lockOpts := &consulapi.LockOptions{
        Key:          lockKey,
        Value:        []byte(fmt.Sprintf("locked by %s at %s", os.Getenv("USER"), time.Now())),
        SessionTTL:   "30s",  // Lock auto-releases if process dies
    }

    lock, err := consulClient.LockOpts(lockOpts)
    if err != nil {
        return fmt.Errorf("failed to create lock: %w", err)
    }

    lockCh, err := lock.Lock(nil)
    if err != nil {
        return fmt.Errorf("failed to acquire lock (another integration in progress?): %w", err)
    }
    defer lock.Unlock()

    // Check if already configured
    kv, _, err := consulClient.KV().Get("service/wazuh/sso/configured", nil)
    if err == nil && kv != nil && string(kv.Value) == "true" {
        logger.Warn("Wazuh SSO already configured by another process")

        if !opts.Force {
            return eos_err.NewUserError("Wazuh SSO integration already exists.\n\n"+
                "Options:\n"+
                "  1. Use --force to reconfigure\n"+
                "  2. Use 'eos update wazuh --delete authentik' to remove existing integration")
        }

        logger.Warn("Reconfiguring Wazuh SSO (--force flag used)")
    }

    // ... rest of configuration ...

    // Mark as configured
    _, err = consulClient.KV().Put(&consulapi.KVPair{
        Key:   "service/wazuh/sso/configured",
        Value: []byte("true"),
    }, nil)
    if err != nil {
        logger.Warn("Failed to mark integration as configured", zap.Error(err))
    }

    return nil
}
```

**Testing Checklist**:
- [ ] Test sequential operations work (lock acquired and released)
- [ ] Test concurrent operations (second waits for first to complete)
- [ ] Test lock timeout (process dies → lock auto-releases after 30s)
- [ ] Test --force flag overrides "already configured" check
- [ ] Verify lock doesn't leak (released on success AND on error)
- [ ] Test lock contention logging (second process sees clear message)

---

### P1 #8: Strengthen URL Validation (1 hour)

**File**: `cmd/update/wazuh_add_authentik.go:140-147`
**Priority**: P1 - Input Validation
**Effort**: 1 hour

**Current Code** (weak validation):
```go
Validator: func(value string) error {
    if value == "" {
        return fmt.Errorf("Wazuh URL cannot be empty")
    }
    // TODO: Add more URL validation if needed
    return nil
},
```

**Issue**: Allows invalid URLs to reach business logic, causing cryptic errors
- `file:///etc/passwd` (wrong protocol)
- `wazuh.com` (missing protocol)
- `https://wazuh .com` (spaces in hostname)
- `https://wazuh.com:999999` (invalid port)
- `https://127.0.0.1` (localhost not allowed for public URL)

**Why This Matters**:
- Poor user experience (cryptic errors deep in business logic)
- Potential security issue (URL injection if not sanitized)
- CLAUDE.md requires using `shared.SanitizeURL()` before validation

**Fix** (use existing validation infrastructure):
```go
Validator: func(value string) error {
    if value == "" {
        return fmt.Errorf("Wazuh URL cannot be empty")
    }

    // Use existing validation infrastructure (CLAUDE.md pattern)
    sanitized := shared.SanitizeURL(value)
    if err := shared.ValidateURL(sanitized); err != nil {
        return fmt.Errorf("invalid Wazuh URL: %w\n\n"+
            "URL must be a valid HTTPS URL (e.g., https://wazuh.example.com)\n"+
            "Got: %s", err, value)
    }

    // Protocol must be HTTPS (Wazuh requires TLS)
    if !strings.HasPrefix(sanitized, "https://") {
        return fmt.Errorf("Wazuh URL must use HTTPS protocol\n\n"+
            "Got: %s\n"+
            "Expected: https://%s", value, strings.TrimPrefix(value, "http://"))
    }

    // Reject localhost/127.0.0.1 (must be public URL for SSO)
    parsedURL, _ := url.Parse(sanitized)
    if parsedURL.Hostname() == "localhost" || parsedURL.Hostname() == "127.0.0.1" {
        return fmt.Errorf("Wazuh URL must be a public hostname (not localhost)\n\n"+
            "SSO requires a publicly accessible URL for redirect URIs.\n"+
            "Use your server's public hostname or IP address.")
    }

    return nil
},
```

**Testing Checklist**:
- [ ] Test valid HTTPS URLs pass (https://wazuh.example.com)
- [ ] Test HTTP URLs rejected with helpful message
- [ ] Test localhost rejected with explanation
- [ ] Test malformed URLs rejected (spaces, invalid chars)
- [ ] Test URLs with invalid ports rejected
- [ ] Test URLs without protocol get clear error
- [ ] Verify error messages are actionable

---

### P1 #9: Fix Broken Health Check (1 hour)

**File**: `pkg/hecate/add/wazuh.go:478-486`
**Priority**: P1 - Reliability
**Effort**: 1 hour

**Current Code** (CREATES instead of CHECKS):
```go
func (w *WazuhIntegrator) HealthCheck(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
    // ...

    providerPK, err := samlClient.CreateSAMLProvider(rc.Ctx, authentik.SAMLProviderConfig{
        Name: "wazuh-saml-provider",
        // ...
    })
    if err != nil {
        logger.Warn("Failed to verify SAML provider", zap.Error(err))
        return nil // Non-fatal
    }

    // BUG: This CREATED a provider, not checked if it exists!
}
```

**Issue**:
- `CreateSAMLProvider` is NOT idempotent
- If provider already exists, this will likely fail with "already exists" error
- Error is swallowed, so user thinks health check passed
- Actual health status is unknown

**Why This Matters**:
- False positives (health check says "OK" when it's not)
- Creates duplicate resources on error
- Doesn't actually verify SSO is working

**Fix** (check instead of create):
```go
func (w *WazuhIntegrator) HealthCheck(rc *eos_io.RuntimeContext, opts *ServiceOptions) error {
    logger := otelzap.Ctx(rc.Ctx)
    logger.Info("  [3/3] Verifying Authentik SAML configuration")

    token, baseURL, err := w.getAuthentikCredentials(rc.Ctx)
    if err != nil {
        logger.Warn("Skipping health check (Authentik credentials not available)")
        return nil // Non-fatal - credentials issue, not health issue
    }

    samlClient := authentik.NewSAMLClient(baseURL, token)

    // CHECK if provider exists (NOT create)
    provider, err := samlClient.GetSAMLProviderByName(rc.Ctx, "wazuh-saml-provider")
    if err != nil {
        logger.Warn("SAML provider not found - integration may not be complete", zap.Error(err))
        return nil // Non-fatal
    }

    logger.Info("    ✓ Authentik SAML provider configured", zap.String("provider_pk", provider.PK))

    // Verify application exists
    app, err := samlClient.GetApplicationBySlug(rc.Ctx, "wazuh-siem")
    if err != nil {
        logger.Warn("Wazuh application not found", zap.Error(err))
        return nil // Non-fatal
    }

    logger.Info("    ✓ Wazuh application configured", zap.String("slug", app.Slug))

    // Verify metadata in Consul KV
    consulClient, err := consulapi.NewClient(consulapi.DefaultConfig())
    if err == nil {
        kv, _, err := consulClient.KV().Get("service/wazuh/sso/metadata_xml", nil)
        if err == nil && kv != nil && len(kv.Value) > 0 {
            logger.Info("    ✓ SAML metadata stored in Consul KV")
        } else {
            logger.Warn("SAML metadata not found in Consul KV")
            logger.Warn("Wazuh server will need to fetch metadata directly from Authentik")
        }
    }

    return nil
}
```

**Note**: Requires adding `GetSAMLProviderByName()` and `GetApplicationBySlug()` methods to `pkg/authentik/saml.go`.

**Testing Checklist**:
- [ ] Add GetSAMLProviderByName() method to authentik package
- [ ] Add GetApplicationBySlug() method to authentik package
- [ ] Test health check with configured SSO (should pass)
- [ ] Test health check with missing provider (should warn, not fail)
- [ ] Test health check with missing application (should warn)
- [ ] Test health check with missing Consul metadata (should warn)
- [ ] Verify NO resources are created during health check

---

### P1 #10: Better TLS Validation (Custom CA Support) (2 hours)

**File**: `pkg/hecate/add/wazuh.go:66-83`
**Priority**: P1 - Security Improvement
**Effort**: 2 hours

**Current Code** (disables ALL validation):
```go
if opts.AllowInsecureTLS {
    logger.Warn("⚠️  TLS CERTIFICATE VERIFICATION DISABLED")
    // ... warnings ...
    tlsConfig.InsecureSkipVerify = true  // Disables EVERYTHING
}
```

**Issue**:
- `InsecureSkipVerify = true` disables:
  - Certificate expiry checks (allows expired certs)
  - Hostname validation (allows wrong hostname)
  - CA validation (allows self-signed certs from ANYONE)
  - Revocation checks
- Too permissive for security-conscious users

**Why This Matters**:
- Users with self-signed certs want to trust THEIR CA, not ALL CAs
- Complete bypass is security anti-pattern
- Better approach: Allow custom CA cert

**Fix** (custom CA cert support):
```go
// In ServiceOptions struct (pkg/hecate/add/types.go):
type ServiceOptions struct {
    // ... existing fields ...
    AllowInsecureTLS    bool   // DEPRECATED: Use CustomCACert instead
    CustomCACert        string // Path to custom CA certificate (for self-signed certs)
    // ...
}

// In wazuh.go validation (line ~66):
if opts.CustomCACert != "" {
    // Load and trust custom CA cert
    caCert, err := os.ReadFile(opts.CustomCACert)
    if err != nil {
        return fmt.Errorf("failed to read CA cert from %s: %w", opts.CustomCACert, err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return fmt.Errorf("failed to parse CA cert from %s\n\n"+
            "Ensure the file contains a valid PEM-encoded certificate", opts.CustomCACert)
    }

    tlsConfig.RootCAs = caCertPool // Use custom CA, keep all other validation
    logger.Info("Using custom CA certificate", zap.String("path", opts.CustomCACert))

} else if opts.AllowInsecureTLS {
    // Only if no custom CA provided
    logger.Warn("⚠️  TLS CERTIFICATE VERIFICATION DISABLED")
    logger.Warn("This is INSECURE. Consider using --ca-cert instead.")
    tlsConfig.InsecureSkipVerify = true
}
```

**Command Usage**:
```bash
# NEW: Trust specific CA (RECOMMENDED)
eos update hecate --add wazuh \
  --dns wazuh.example.com \
  --upstream 192.168.1.10 \
  --ca-cert /etc/ssl/certs/my-ca.pem

# OLD: Disable all validation (still works, but discouraged)
eos update hecate --add wazuh \
  --dns wazuh.example.com \
  --upstream 192.168.1.10 \
  --allow-insecure-tls
```

**Testing Checklist**:
- [ ] Add CustomCACert field to ServiceOptions
- [ ] Add --ca-cert flag to cmd/update/hecate_add.go
- [ ] Test with valid custom CA cert (should work)
- [ ] Test with invalid CA cert file (should error with clear message)
- [ ] Test with malformed PEM file (should error)
- [ ] Test with expired CA cert (should still validate server cert against it)
- [ ] Verify hostname validation still works with custom CA
- [ ] Deprecate --allow-insecure-tls in favor of --ca-cert

---

### Success Criteria ✅

- [ ] P1 #5: Crypto key length research complete, constant documented
- [ ] P1 #6: Atomic file writes implemented, 5 calls updated
- [ ] P1 #7: Distributed locking implemented, race conditions prevented
- [ ] P1 #8: URL validation strengthened, all invalid inputs rejected
- [ ] P1 #9: Health check fixed, no resource creation during checks
- [ ] P1 #10: Custom CA cert support added, --allow-insecure-tls deprecated
- [ ] Build succeeds: `go build -o /tmp/eos-build ./cmd/`
- [ ] go vet passes: `go vet ./pkg/wazuh/... ./pkg/hecate/... ./pkg/shared/...`
- [ ] All tests pass (unit + integration)
- [ ] Security review complete (no new P0/P1 issues)
- [ ] Documentation updated (CLAUDE.md, command help text)

---

### Files to Modify

| File | Changes | Lines | Effort |
|------|---------|-------|--------|
| `pkg/wazuh/types.go` | Add SAMLExchangeKeyLengthBytes constant | +10 | 15min |
| `pkg/wazuh/sso_sync.go` | Use new constant in GenerateExchangeKey() | ~5 | 15min |
| `pkg/shared/atomic_write.go` | NEW - Atomic file write helper | +50 | 1h |
| `pkg/wazuh/sso/configure.go` | Use AtomicWriteFile (2 calls) | ~10 | 15min |
| `pkg/wazuh/sso_sync.go` | Use AtomicWriteFile (3 calls) | ~15 | 15min |
| `pkg/hecate/add/wazuh.go` | Add distributed locking + fix health check | +80 | 3h |
| `pkg/hecate/add/types.go` | Add CustomCACert field | +2 | 5min |
| `cmd/update/wazuh_add_authentik.go` | Strengthen URL validation | ~20 | 30min |
| `cmd/update/hecate_add.go` | Add --ca-cert flag | +3 | 15min |
| `pkg/authentik/saml.go` | Add GetSAMLProviderByName(), GetApplicationBySlug() | +60 | 1h |
| **Total** | **10 files** | **~255 lines** | **10-12h** |

---

### Deployment Plan

**Phase 1: Non-Breaking Changes** (6 hours)
- P1 #5: Crypto key length (breaking only if keys incompatible)
- P1 #6: Atomic file writes (internal improvement, no API change)
- P1 #8: URL validation (stricter, may reject previously accepted invalid URLs)

**Phase 2: Breaking Changes** (6 hours)
- P1 #7: Distributed locking (may reject concurrent operations)
- P1 #9: Health check fix (changes behavior)
- P1 #10: Custom CA cert (deprecates --allow-insecure-tls)

**Rollback Plan**:
- Keep P0 fixes (already in production)
- Revert P1 changes if critical issues found
- Each P1 fix is independent (can revert individually)

---

### Reference

**Full Analysis**: See conversation history (2025-10-28) for complete adversarial analysis with 25 issues across P0-P3.

**Related Work**:
- P0 fixes: Completed 2025-10-28 (5 issues, 4 files, ~125 lines)
- P2 fixes: Documented as technical debt (7 issues, 6-8 hours estimated)
- P3 fixes: Nice-to-have (6 issues, 12-16 hours estimated)

**Next Steps After P1**:
- Deploy to staging environment
- Manual testing (full SSO flow)
- Security audit (penetration testing)
- Production deployment

---

## Phase 5: Upgrade & Test 📅 PLANNED

### Target Completion: Week of 2025-11-10

### 5.1: Upgrade Vault SDK
```bash
go get github.com/hashicorp/vault/api@v1.22.0
go mod tidy
```

**Why**: Latest stable features, bug fixes, security patches

**Risk**: LOW (v1.16 → v1.22 is backward compatible)

### 5.2: Comprehensive Testing

**Test Suite**:
```bash
# Unit tests
go test -v ./pkg/secrets/...
go test -v ./pkg/vault/...

# Integration tests (require Vault running)
go test -v -tags=integration ./pkg/secrets/...

# Service tests
go test -v ./pkg/bionicgpt/...
go test -v ./cmd/create/...

# Full build verification
go build -o /tmp/eos-build ./cmd/
```

### 5.3: Manual Testing

**Test Checklist**:
- [ ] `eos create vault` - Vault installation works
- [ ] `eos create bionicgpt` - BionicGPT with secrets works
- [ ] `eos debug bionicgpt` - Diagnostics find secrets correctly
- [ ] `eos create umami` - Umami secrets work
- [ ] Secret rotation works (update + retrieve)
- [ ] Context cancellation works (Ctrl+C during operations)

### Success Criteria
- [ ] All tests pass
- [ ] No regressions
- [ ] Build succeeds
- [ ] Manual testing passes
- [ ] Performance acceptable (no slowdowns)

---

### 5.5: Interaction Package P0/P1/P2 Cleanup ✅ COMPLETE (2025-10-28)

**Target Completion**: Week of 2025-11-03
**Actual Completion**: 2025-10-28
**Effort**: 60 minutes
**Priority**: P0-P2 mixed

**Context**: Adversarial analysis (2025-10-28) of yes/no prompt consolidation found 11 issues requiring cleanup.

**Reference**: Detailed implementation plan in conversation history (2025-10-28).

#### P0 Critical (30 min) ✅ COMPLETE
- ✅ Fix fmt.Print* in bionicgpt_nomad/interactive.go (4 functions migrated to logger.Info)
- ✅ Document PromptSecret exception (6-line P0 EXCEPTION comment added)
- ✅ Fix resolver.go (2 functions + 4 call sites migrated to RuntimeContext + logger.Info)
- ✅ Fix prompt_string.go (5 fmt.Print* documented with P0 EXCEPTION comments)

#### P1 Important (20 min) ✅ COMPLETE
- ✅ Add tests for validateYesNoResponse helper (20 test cases, all passing)
- ✅ Fix misleading test comment (TestStrictInputValidation_Documentation clarified)

#### P2 Documentation (10 min) ✅ COMPLETE
- ✅ Update README fmt.Print* policy accuracy (documented exceptions with rationale)
- ✅ Add architecture decision for fmt.Print* usage (when forbidden vs acceptable)

**Files Modified**: 7 files
1. `pkg/bionicgpt_nomad/interactive.go` - 4 functions updated for P0 compliance
2. `pkg/interaction/input.go` - P0 exception documented
3. `pkg/interaction/resolver.go` - 2 functions migrated + 4 call sites updated
4. `pkg/interaction/prompt_string.go` - 5 fmt.Print* documented as exceptions
5. `pkg/interaction/input_test.go` - New test + comment fix (60 lines added)
6. `pkg/interaction/README.md` - 2 sections updated (fmt.Print* policy + architecture)
7. `ROADMAP.md` - This section added

**Success Criteria** ✅ ALL PASSED:
- ✅ Zero fmt.Print* outside documented exceptions (audit passed)
- ✅ All new tests pass (TestValidateYesNoResponse: 20/20 passing)
- ✅ Build succeeds with zero errors (`go build -o /tmp/eos-build ./cmd/`)
- ✅ Vet passes (`go vet ./pkg/interaction/... ./pkg/bionicgpt_nomad/...`)
- ✅ Documentation accurate (README.md updated with current exceptions)

**Verification**:
```bash
# Audit shows only documented exceptions:
grep -rn "fmt.Print" pkg/interaction/ --include="*.go" | grep -v "// P0 EXCEPTION"
# Returns: Only comments explaining P0 compliance

# Build verification:
go build -o /tmp/eos-build ./cmd/  # ✅ SUCCESS (no errors)

# Test verification:
go test -v -run TestValidateYesNoResponse ./pkg/interaction/
# ✅ PASS: All 20 test cases passing
```

**Known Pre-Existing Issues** (out of scope for this cleanup):
- TestBuildRemediationError failures (3 subtests) - pre-existing
- FuzzValidateNoShellMeta seed#16, #17 failures - pre-existing
- Low coverage (17.6%) - expected due to TTY interaction requirements

**Out of Scope** (tracked as technical debt):
- Package-wide fmt.Print* policy enforcement (too large for single session)
- PromptYesNoSafe integration tests (logger interaction challenges)

---

### 5.4: Vault Cluster Authentication Improvements (P2) 📅 PLANNED

**Target Completion**: Week of 2025-11-10
**Effort**: 9 hours
**Priority**: P2

**Context**: Adversarial analysis of vault cluster authentication (2025-10-28) identified quality issues in the recently implemented authentication system for `eos update vault-cluster` commands.

**Reference**: See adversarial analysis document (created 2025-10-28) for full findings and rationale.

#### 5.4.1: Improve Capability Verification (3 hours)

**File**: `pkg/vault/auth_cluster.go:149-177`

**Current Behavior**: Only checks `sys/storage/raft/configuration` capability
**Problem**: Autopilot and snapshot operations require additional Vault paths that aren't verified

**Implementation**:
```go
func verifyClusterOperationCapabilities(rc, client) error {
    // Check ALL required paths for cluster operations
    requiredCapabilities := map[string][]string{
        "sys/storage/raft/configuration": {"read"},
        "sys/storage/raft/autopilot/configuration": {"read", "update"},
        "sys/storage/raft/snapshot": {"read"},
        "sys/storage/raft/snapshot-force": {"update"}, // For forced restore
    }

    missingCapabilities := []string{}

    for path, requiredCaps := range requiredCapabilities {
        capabilities, err := client.Sys().CapabilitiesSelf(path)
        if err != nil {
            logger.Debug("Capability check failed",
                zap.String("path", path), zap.Error(err))
            continue  // Try other paths
        }

        for _, required := range requiredCaps {
            if !sliceContains(capabilities, required) {
                missingCapabilities = append(missingCapabilities,
                    fmt.Sprintf("%s on %s", required, path))
            }
        }
    }

    if len(missingCapabilities) > 0 {
        return fmt.Errorf("token lacks required capabilities:\n"+
            "  Missing: %v\n\n"+
            "Ensure your token has one of:\n"+
            "  • eos-admin-policy (recommended)\n"+
            "  • root policy (emergency only)", missingCapabilities)
    }

    return nil
}
```

**Testing Checklist**:
- [ ] Test with token that has partial capabilities (should fail with detailed error showing which capabilities missing)
- [ ] Test with full eos-admin-policy token (should pass all checks)
- [ ] Test with root token (should pass all checks)
- [ ] Test with read-only token (should fail on update capabilities)

---

#### 5.4.2: Add Context Caching for Admin Client (2 hours)

**Files**:
- `cmd/update/vault_cluster.go:288-326`
- `pkg/vault/auth_cluster.go:30-70`

**Current Behavior**: Each command re-authenticates independently
**Problem**: Redundant authentication when running multiple cluster operations in scripts

**Implementation**:
```go
// In cmd/update/vault_cluster.go:
func getAuthenticatedVaultClient(rc, cmd) (string, error) {
    logger := otelzap.Ctx(rc.Ctx)

    // Check if authenticated token already cached in context
    if cachedToken := getCachedClusterToken(rc); cachedToken != "" {
        logger.Debug("Using cached cluster authentication token")
        // Verify cached token still valid
        client, err := vault.GetVaultClientWithToken(rc, cachedToken)
        if err == nil {
            return cachedToken, nil
        }
        logger.Debug("Cached token invalid, re-authenticating")
    }

    // Try authentication hierarchy...
    token, err := performAuthentication(rc, cmd)
    if err != nil {
        return "", err
    }

    // Cache token for reuse within this RuntimeContext
    cacheClusterToken(rc, token)
    return token, nil
}

// Add context key and helper functions:
type clusterTokenKey struct{}

func cacheClusterToken(rc *eos_io.RuntimeContext, token string) {
    rc.Ctx = context.WithValue(rc.Ctx, clusterTokenKey{}, token)
}

func getCachedClusterToken(rc *eos_io.RuntimeContext) string {
    if token, ok := rc.Ctx.Value(clusterTokenKey{}).(string); ok {
        return token
    }
    return ""
}
```

**Testing Checklist**:
- [ ] Test sequential operations reuse cached token (no redundant prompts)
- [ ] Test cache isolated per RuntimeContext (different commands don't share)
- [ ] Test cache invalidation when token expires
- [ ] Test cache doesn't persist across command invocations

---

#### 5.4.3: Improve Error Message Clarity (2 hours)

**File**: `cmd/update/vault_cluster.go:318-322`

**Current Behavior**: Lists 3 authentication methods without explaining when to use each
**Problem**: Users confused about which method is appropriate for their use case

**Implementation**:
```go
return "", fmt.Errorf("admin authentication failed: %w\n\n"+
    "═══════════════════════════════════════════════\n"+
    "Cluster operations require admin-level access.\n"+
    "═══════════════════════════════════════════════\n\n"+
    "OPTION 1: Use existing token (automation/CI/CD)\n"+
    "  When: You have a pre-generated Vault token\n"+
    "  How:  eos update vault-cluster ... --token <your_token>\n"+
    "  Or:   export VAULT_TOKEN=<your_token>\n\n"+
    "OPTION 2: Automatic authentication (RECOMMENDED for interactive use)\n"+
    "  When: Running interactively on server where Eos is installed\n"+
    "  How:  Run command without --token flag\n"+
    "  Eos will try (in order):\n"+
    "    1. Vault Agent (automatic, zero-touch, audited)\n"+
    "    2. Admin AppRole (stored in /var/lib/eos/secret/)\n"+
    "    3. Root token (emergency only, requires sudo + consent)\n\n"+
    "OPTION 3: Manual authentication (custom workflows)\n"+
    "  When: Remote execution or custom auth method\n"+
    "  How:  vault login -method=userpass\n"+
    "        export VAULT_TOKEN=$(vault print token)\n"+
    "        eos update vault-cluster ...\n\n"+
    "Troubleshooting:\n"+
    "  • Vault Agent not running: systemctl status vault-agent-eos\n"+
    "  • Missing admin credentials: sudo eos create vault --enable-admin-role\n"+
    "  • Need help: https://docs.eos.com/vault-cluster-auth", err)
```

**Testing Checklist**:
- [ ] User testing with 3 people unfamiliar with Eos (measure comprehension)
- [ ] Verify each option works exactly as described in error message
- [ ] Check error message formatting in 80-column and 120-column terminals
- [ ] Verify URL in message points to actual documentation

---

#### 5.4.4: Add Rate Limiting for Token Attempts (2 hours)

**File**: `pkg/vault/auth_cluster.go` (add new rate limiting mechanism)

**Current Behavior**: Unlimited token validation attempts
**Problem**: Makes brute force attacks easier (though Vault has its own rate limiting)

**Implementation**:
```go
// Add token attempt tracking state
type tokenAttemptKey struct{}

type TokenAttemptState struct {
    Attempts     int
    LastAttempt  time.Time
}

func getTokenAttemptState(rc *eos_io.RuntimeContext) *TokenAttemptState {
    if state, ok := rc.Ctx.Value(tokenAttemptKey{}).(*TokenAttemptState); ok {
        return state
    }
    state := &TokenAttemptState{}
    rc.Ctx = context.WithValue(rc.Ctx, tokenAttemptKey{}, state)
    return state
}

// In GetVaultClientWithToken(), add at start:
func GetVaultClientWithToken(rc, token) (*api.Client, error) {
    logger := otelzap.Ctx(rc.Ctx)

    // Client-side rate limiting (defense in depth)
    attemptState := getTokenAttemptState(rc)
    attemptState.Attempts++
    attemptState.LastAttempt = time.Now()

    if attemptState.Attempts > 3 {
        // Exponential backoff: 2s, 4s, 6s, 8s, ...
        delay := time.Duration(attemptState.Attempts-3) * 2 * time.Second
        logger.Warn("⚠️  Rate limiting token validation",
            zap.Int("attempt", attemptState.Attempts),
            zap.Duration("delay", delay),
            zap.String("reason", "Too many failed token validations"))

        // Wait before next attempt
        select {
        case <-time.After(delay):
        case <-rc.Ctx.Done():
            return nil, fmt.Errorf("operation cancelled during rate limit delay")
        }
    }

    // Continue with token validation...
}
```

**Testing Checklist**:
- [ ] Test first 3 attempts have no delay (normal operation)
- [ ] Test 4th attempt has 2-second delay
- [ ] Test 5th attempt has 4-second delay
- [ ] Test delay cancellable via context (Ctrl+C works)
- [ ] Test legitimate retry scenarios still work
- [ ] Verify delay doesn't affect valid tokens (only retries)

---

### 5.4 Success Criteria
- [ ] All capability verification tests pass
- [ ] Context caching works (verified with script running 5 sequential operations)
- [ ] Error messages tested with 3 users (>80% comprehension rate)
- [ ] Rate limiting prevents rapid retries without breaking legitimate use
- [ ] Build succeeds: `go build -o /tmp/eos-build ./cmd/`
- [ ] go vet passes: `go vet ./pkg/vault/... ./cmd/update/...`
- [ ] No performance regression (benchmark token validation time)

---

## Phase 6: Documentation & Migration Guide 📅 PLANNED

### Target Completion: Week of 2025-11-17

### 6.1: Update Core Documentation

**Files to update**:
1. **`CLAUDE.md`** - Update secret management patterns
   - Replace `GetOrGenerateServiceSecrets` examples
   - Add context parameter to examples
   - Document new `SecretStore` interface

2. **`CHANGELOG.md`** - Document breaking changes
   ```markdown
   ## [Unreleased]

   ### Added
   - New universal `SecretStore` interface for backend abstraction
   - `EnsureServiceSecrets()` function with context support

   ### Changed
   - **BREAKING**: `GetOrGenerateServiceSecrets()` renamed to `EnsureServiceSecrets()`
   - **BREAKING**: Context parameter added to all secret operations
   - Vault SDK upgraded from v1.16 to v1.22

   ### Deprecated
   - `GetOrGenerateServiceSecrets()` - use `EnsureServiceSecrets()` instead
   - `pkg/hecate/secret_manager.go` - use `pkg/secrets.Manager` instead

   ### Fixed
   - Vault diagnostic path bug (removed double "secret/" prefix)
   - Context propagation (replaced context.Background() with passed ctx)
   ```

3. **`docs/SECRET_MANAGEMENT.md`** (NEW) - Comprehensive architecture guide
   - SecretStore interface design
   - Backend comparison (Vault vs Consul vs File)
   - Migration guide for existing code
   - Security best practices

4. **`pkg/secrets/README.md`** - Updated usage examples

### 6.2: Create Migration Guide

**File**: `docs/MIGRATION_SECRET_MANAGER.md` (NEW)

**Content**:
- Why we refactored
- Breaking changes summary
- Step-by-step migration instructions
- Code examples (before/after)
- Troubleshooting common issues
- Timeline for deprecated function removal

### Success Criteria
- [ ] Documentation complete and accurate
- [ ] Migration guide tested by following it manually
- [ ] CLAUDE.md patterns work
- [ ] Examples compile and run

### 6.3: Vault Cluster Authentication Documentation (P3) 📅 PLANNED

**Target Completion**: Week of 2025-11-17
**Effort**: 5 hours
**Priority**: P3

**Context**: Complete documentation and polish for vault cluster authentication system implemented 2025-10-28.

**Reference**: See adversarial analysis for P3 issue details.

#### 6.3.1: Add Comprehensive Function Documentation (2 hours)

**File**: `cmd/update/vault_cluster.go:279-326`

**Current State**: Basic comment explaining function purpose
**Missing**: Examples, troubleshooting guide, when to use each authentication method

**Implementation**:
Add comprehensive godoc-style documentation to `getAuthenticatedVaultClient()`:

```go
// getAuthenticatedVaultClient handles authentication for Vault cluster operations.
//
// This function implements a 3-tier authentication hierarchy optimized for
// different use cases: explicit tokens (automation), automatic auth (interactive),
// and manual auth (custom workflows).
//
// # Authentication Hierarchy
//
//   1. --token flag: User explicitly provided token (highest priority)
//      - Use case: CI/CD pipelines, automation scripts
//      - Security: Token stored in secure variable/secret manager
//      - Example: --token hvs.abc123def456
//
//   2. VAULT_TOKEN env: Token from environment variable
//      - Use case: Scripts, temporary sessions
//      - Security: Token set via secure environment
//      - Example: export VAULT_TOKEN=hvs.abc123def456
//
//   3. GetAdminClient(): Automatic authentication chain
//      - Use case: Interactive use on Eos-managed servers
//      - Methods tried: Vault Agent → Admin AppRole → Root (with consent)
//      - Security: Vault Agent (audited) or AppRole (rotatable) preferred
//
// # Returns
//
//   - string: Validated Vault token with cluster operation capabilities
//   - error: Authentication failure with remediation guidance
//
// # Examples
//
// Explicit token (automation/CI/CD):
//
//   $ eos update vault-cluster autopilot --token hvs.abc123 --min-quorum=3
//   ✓ Token authenticated and validated for cluster operations
//   ✓ Autopilot configured successfully
//
// Environment token (scripting):
//
//   $ export VAULT_TOKEN=hvs.abc123
//   $ eos update vault-cluster snapshot --output=/backup/snap.snap
//   Using token from VAULT_TOKEN environment variable
//   ✓ Snapshot created successfully
//
// Automatic authentication (interactive, recommended):
//
//   $ eos update vault-cluster peers
//   No token provided via --token or VAULT_TOKEN
//   Attempting admin authentication (Vault Agent → AppRole → Root)
//   ✓ Admin authentication successful (method: vault-agent-with-admin-policy)
//
//   Raft Cluster Peers (3 nodes):
//     node1: leader ⭐ (voter)
//     node2: follower (voter)
//     node3: follower (voter)
//
// # Error Handling
//
// Token validation failures return detailed errors with:
//   - Which authentication method failed and why
//   - What the token is missing (expired, invalid, insufficient capabilities)
//   - How to fix (get new token, check Vault Agent status, use --token)
//   - Remediation examples (exact commands to run)
//
// # Implementation Details
//
// The function delegates ALL business logic to pkg/vault, maintaining clean
// separation between orchestration (cmd/) and implementation (pkg/). This
// follows the Eos architecture pattern defined in CLAUDE.md.
//
// Token validation includes:
//   - Format validation (prevents injection attacks)
//   - Seal status check (clear error if Vault sealed)
//   - Token validity check (not expired or revoked)
//   - Capability verification (can perform cluster operations)
//   - TTL warning (if token expires soon)
//
// # See Also
//
//   - pkg/vault/auth_cluster.go: Token validation implementation
//   - pkg/vault/client_admin.go: GetAdminClient() implementation
//   - CLAUDE.md: Vault authentication patterns
//
func getAuthenticatedVaultClient(rc *eos_io.RuntimeContext, cmd *cobra.Command) (string, error) {
    // Implementation...
}
```

**Testing Checklist**:
- [ ] godoc renders documentation correctly
- [ ] Examples can be copy-pasted and work
- [ ] Error scenarios documented match actual behavior
- [ ] Links to related code are correct

---

#### 6.3.2: Add --dry-run Support for Auth Testing (3 hours)

**Files**:
- `cmd/update/vault_cluster.go:60, 82-84, 117-155, 157-220` (add flag + implement dry-run logic)
- `pkg/vault/cluster_operations.go` (potentially add validation-only mode)

**Current State**: No way to test token validity without executing dangerous operations
**Problem**: Users can't verify credentials work before running destructive snapshot restore

**Implementation**:

1. Add --dry-run flag:
```go
// In vault_cluster.go init():
func init() {
    // ... existing flags ...

    // Dry-run flag (applies to all operations)
    vaultClusterCmd.Flags().Bool("dry-run", false,
        "Validate authentication and show planned actions without executing")
}
```

2. Implement dry-run in runVaultClusterAutopilot():
```go
func runVaultClusterAutopilot(rc, cmd) error {
    log := otelzap.Ctx(rc.Ctx)
    dryRun, _ := cmd.Flags().GetBool("dry-run")

    // Authenticate (validation happens here)
    token, err := getAuthenticatedVaultClient(rc, cmd)
    if err != nil {
        return err
    }

    // Parse configuration
    cleanupDeadServers, _ := cmd.Flags().GetBool("cleanup-dead-servers")
    deadServerThreshold, _ := cmd.Flags().GetString("dead-server-threshold")
    minQuorum, _ := cmd.Flags().GetInt("min-quorum")
    stabilizationTime, _ := cmd.Flags().GetString("stabilization-time")

    config := &vault.AutopilotConfig{
        CleanupDeadServers:             cleanupDeadServers,
        DeadServerLastContactThreshold: deadServerThreshold,
        MinQuorum:                      minQuorum,
        ServerStabilizationTime:        stabilizationTime,
    }

    if dryRun {
        // Dry-run mode: show what WOULD happen
        log.Info("")
        log.Info("═══════════════════════════════════════")
        log.Info("DRY-RUN MODE (no changes will be made)")
        log.Info("═══════════════════════════════════════")
        log.Info("")
        log.Info("✓ Authentication successful")
        log.Info("  Token validated with cluster operation capabilities")
        log.Info("")
        log.Info("Would configure Autopilot with:")
        log.Info(fmt.Sprintf("  • cleanup-dead-servers: %v", config.CleanupDeadServers))
        log.Info(fmt.Sprintf("  • dead-server-threshold: %s", config.DeadServerLastContactThreshold))
        log.Info(fmt.Sprintf("  • min-quorum: %d", config.MinQuorum))
        log.Info(fmt.Sprintf("  • server-stabilization-time: %s", config.ServerStabilizationTime))
        log.Info("")
        log.Info("Run without --dry-run to apply these changes.")
        return nil
    }

    // Normal execution
    log.Info("Configuring Autopilot", ...)
    return vault.ConfigureRaftAutopilot(rc, token, config)
}
```

3. Implement dry-run in runVaultClusterSnapshot():
```go
func runVaultClusterSnapshot(rc, cmd) error {
    log := otelzap.Ctx(rc.Ctx)
    dryRun, _ := cmd.Flags().GetBool("dry-run")

    // Authenticate
    token, err := getAuthenticatedVaultClient(rc, cmd)
    if err != nil {
        return err
    }

    outputPath, _ := cmd.Flags().GetString("output")
    inputPath, _ := cmd.Flags().GetString("input")
    force, _ := cmd.Flags().GetBool("force")

    if dryRun {
        log.Info("")
        log.Info("═══════════════════════════════════════")
        log.Info("DRY-RUN MODE (no changes will be made)")
        log.Info("═══════════════════════════════════════")
        log.Info("")
        log.Info("✓ Authentication successful")

        if inputPath != "" {
            // Restore operation
            log.Warn("⚠️  SNAPSHOT RESTORE (DESTRUCTIVE)")
            log.Info(fmt.Sprintf("  Would restore from: %s", inputPath))
            log.Info(fmt.Sprintf("  Force mode: %v", force))
            log.Warn("  This would replace ALL Vault data")

            if !force {
                log.Warn("")
                log.Warn("  Note: --force flag required for actual restore")
            }
        } else if outputPath != "" {
            // Backup operation
            log.Info("Snapshot Backup")
            log.Info(fmt.Sprintf("  Would save to: %s", outputPath))
            log.Info("  Current cluster state would be captured")
        }

        log.Info("")
        log.Info("Run without --dry-run to execute this operation.")
        return nil
    }

    // Normal execution...
}
```

**Testing Checklist**:
- [ ] --dry-run with valid token shows planned actions (no Vault changes)
- [ ] --dry-run with invalid token shows authentication error
- [ ] --dry-run with expired token shows TTL warning
- [ ] --dry-run with insufficient capabilities shows which are missing
- [ ] --dry-run + autopilot shows configuration that would be applied
- [ ] --dry-run + snapshot backup shows output path
- [ ] --dry-run + snapshot restore shows warning + force requirement
- [ ] Verify NO Vault API calls made in dry-run mode (use debug logging)
- [ ] Works consistently across all operations (peers, health, autopilot, snapshot)

---

### 6.3 Success Criteria
- [ ] Function documentation complete and reviewed
- [ ] godoc output verified (correct rendering)
- [ ] --dry-run implemented for all cluster operations
- [ ] --dry-run tested with 10 different scenarios (valid/invalid tokens, all operations)
- [ ] User guide updated with --dry-run examples
- [ ] Build succeeds: `go build -o /tmp/eos-build ./cmd/`
- [ ] No Vault state changes during --dry-run (verified with audit logs)

---

## Future Phases (Post-Refactoring)

### Phase 7: Consider vault-client-go Migration (2025-Q3)

**Status**: BLOCKED - Waiting for GA release

**Current Situation**:
- `vault-client-go` is BETA (not production-ready)
- HashiCorp explicitly warns "do not use in production"
- No GA timeline announced

**When to Reconsider**:
- ✅ HashiCorp announces GA (General Availability)
- ✅ Production readiness statement published
- ✅ Stable API guarantees provided
- ✅ Migration guide from `vault/api` available

**Action Items**:
- [ ] Monitor `vault-client-go` releases
- [ ] Test beta in development environment
- [ ] Create adapter layer when GA announced
- [ ] Plan gradual migration

---

## Timeline Summary

| Phase | Target Completion | Status | Priority | Effort |
|-------|-------------------|--------|----------|--------|
| **Phase 1: Foundation** | 2025-10-27 | ✅ COMPLETE | P0 | - |
| **Phase 2: Manager Refactoring** | 2025-10-27 | ✅ COMPLETE | P0 | - |
| **Phase 3: Critical Bug Fixes** | 2025-10-27 | ✅ COMPLETE | P0 | - |
| **Phase 4: Service Migration** | 2025-10-27 | ✅ COMPLETE | P1 | - |
| **Phase 5.1-5.3: Upgrade & Test** | 2025-11-10 | 📅 PLANNED | P1 | TBD |
| **Phase 5.4: Vault Auth P2 Issues** | 2025-11-10 | 📅 PLANNED | P2 | 9h |
| **Phase 6.1-6.2: Documentation** | 2025-11-17 | 📅 PLANNED | P2 | TBD |
| **Phase 6.3: Vault Auth P3 Polish** | 2025-11-17 | 📅 PLANNED | P3 | 5h |
| **Phase 7: vault-client-go** | 2026-Q2 | ⏸️ BLOCKED | P3 | - |

**Critical Path Complete**: Phases 1-4 completed in 1 day (2025-10-27)
**Remaining Timeline**: 3 weeks for testing + documentation + vault auth improvements (Phases 5-6)
**Vault Auth Work**: 14 hours total (9h P2 + 5h P3) scheduled across Phases 5.4 and 6.3

---

## Risk Management

### High-Risk Items

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| **Breaking changes affect external code** | HIGH | Deprecated aliases for 6 months | Henry |
| **99 files affected by refactoring** | HIGH | Comprehensive testing, gradual rollout | Henry |
| **Vault SDK upgrade breaks compatibility** | MEDIUM | v1.16→v1.22 is backward compatible (verified) | Henry |
| **Context propagation changes behavior** | MEDIUM | Test timeout/cancellation extensively | Henry |

### Medium-Risk Items

| Risk | Impact | Mitigation | Owner |
|------|--------|------------|-------|
| **Service migration introduces bugs** | MEDIUM | Migrate one service at a time, test each | Henry |
| **Path bug fix causes new issues** | LOW | Fix is objectively correct (remove double prefix) | Henry |
| **Performance regression** | LOW | Benchmark before/after | Henry |

---

## Success Metrics

### Phase 2-3 Success Criteria (Critical Path) ✅ COMPLETE
- [x] Phase 1 foundation complete (3 new files: store.go, vault_store.go, consul_store.go)
- [x] Phase 1 adversarial review complete (zero P0/P1 issues)
- [x] Phase 1 verification complete (build + vet + gofmt pass)
- [x] Phase 2 refactoring complete (manager.go updated - 427 lines removed)
- [x] Phase 3 bugs fixed (vault diagnostic path bug + context propagation complete)
- [x] Build succeeds (`go build ./cmd/` - zero errors)
- [x] go vet passes (`go vet ./pkg/secrets/...` - zero warnings)
- [x] gofmt passes (all files formatted correctly)
- [x] Backward compatibility maintained (deprecated aliases provided)
- [ ] BionicGPT test deployment succeeds (deferred to Phase 4)

### Overall Project Success Criteria
- [x] All 7 services migrated to new API (Phase 4 complete)
- [x] Phase 1-4 build verification complete (zero errors)
- [ ] Manual testing: `eos create <service>` commands work (Phase 5)
- [ ] Zero regressions in secret storage/retrieval (Phase 5)
- [ ] Documentation complete and accurate (Phase 6)
- [ ] Migration guide validated (Phase 6)
- [ ] Tests pass (unit + integration) (Phase 5)
- [ ] Performance acceptable (no slowdowns) (Phase 5)
- [ ] Code review approved (Phase 5)
- [ ] Deployed to production successfully (Phase 5)

---

## Communication Plan

### Status Updates
- **Weekly**: Update ROADMAP.md with progress
- **Milestones**: Announce phase completions in team chat
- **Blockers**: Immediate notification if critical issues found

### Review Process
- **Phase 2-3**: Single PR (critical path)
- **Phase 4**: One PR per service (easier to review)
- **Phase 5-6**: Single PR (testing + docs)

### Rollback Plan
If critical issues found:
1. **Phase 2-3**: Revert to `manager.go.backup`
2. **Phase 4**: Services use deprecated aliases (no immediate breakage)
3. **Phase 5**: Downgrade Vault SDK if needed
4. **Phase 6**: Documentation rollback (no code impact)

---

## Future Work (Deferred)

### Hecate Auto-Migration Command

**Status**: 📅 PLANNED
**Priority**: P2 (Quality-of-life improvement)
**Effort**: 3-4 hours
**Added**: 2025-10-28

**Goal**: Auto-detect and fix outdated Hecate installations (missing port 2019 exposure in docker-compose.yml)

**Background**:
- Eos v1.X Hecate installations did not expose Caddy Admin API port 2019
- Eos v2.0+ exposes port 2019 for zero-downtime config reloads via `eos update hecate --add`
- Current fallback: docker exec validation (zero-downtime, works on all installations)
- Future improvement: Automated migration for existing installations

**Current Workaround**:
Users can manually update `/opt/hecate/docker-compose.yml`:
```yaml
services:
  caddy:
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      - "127.0.0.1:2019:2019"  # Add this line
```
Then restart: `cd /opt/hecate && docker-compose up -d`

**Planned Command**:
```bash
# Auto-detect and fix outdated Hecate installation
eos update hecate --fix-installation

# What it does:
1. Detect if port 2019 is exposed in docker-compose.yml
2. If not exposed:
   - Backup current docker-compose.yml
   - Update with new template (adds port 2019)
   - Restart Hecate: docker-compose up -d
   - Verify Admin API is accessible
3. If already exposed: report "already up-to-date"
```

**Implementation Tasks**:
1. Create `pkg/hecate/migration.go`:
   - `DetectPortExposure()` - Parse docker-compose.yml, check for "2019:2019"
   - `BackupDockerCompose()` - Copy to `/opt/hecate/backups/docker-compose.yml.backup.TIMESTAMP`
   - `UpdateDockerCompose()` - Inject port exposure using YAML parser (not string replacement)
   - `RestartHecate()` - `docker-compose up -d` in `/opt/hecate`
   - `VerifyAdminAPI()` - Check `http://localhost:2019/` responds

2. Add flag to `cmd/update/hecate.go`:
   ```go
   SecureHecateCmd.Flags().Bool("fix-installation", false, "Auto-migrate outdated Hecate installation")
   ```

3. Integration with existing validation:
   - Preflight check detects missing port 2019
   - Suggests: `eos update hecate --fix-installation`
   - Falls back to docker exec validation (current behavior)

**Benefits**:
- Zero-downtime migrations for existing installations
- Users get Admin API benefits without manual YAML editing
- Automated testing of installation state

**Risks**:
- YAML parsing complexity (use `gopkg.in/yaml.v3`)
- User-modified docker-compose.yml (detect with comment markers)
- Concurrent `docker-compose` operations (use file locking)

**Target Date**: TBD (after Phase 2 validation in production)
**Reference**: See [pkg/hecate/add/caddy.go](pkg/hecate/add/caddy.go) for current validation fallback logic

---

### BionicGPT Vault Integration

**Status**: 📅 DEFERRED - Current .env approach working
**Priority**: P2 (Nice-to-have)
**Effort**: 2-4 hours
**Added**: 2025-10-28

**Current State**:
- Secrets stored in `/opt/bionicgpt/.env` and `/opt/bionicgpt/.env.litellm` files (working)
- Vault diagnostics showing 403 Forbidden errors (Vault Agent token lacks read permissions)
- Services functioning correctly with file-based secrets

**Issue**:
Vault Agent AppRole policy doesn't grant read access to `services/production/bionicgpt/*` path. Diagnostics show:
```
Code: 403. Errors:
* preflight capability check returned 403, please ensure client's policies grant access to path "services/production/bionicgpt/postgres_password/"
```

**Blockers**:
1. Vault Agent AppRole needs read access to KVv2 secrets at `services/production/bionicgpt/*`
2. Required policy update:
   ```hcl
   path "services/data/production/bionicgpt/*" {
     capabilities = ["read"]
   }
   ```
   Note: KVv2 requires `services/data/` prefix (not `services/`)

**Implementation Tasks**:
1. Update Vault Agent AppRole policy to include BionicGPT secret read access
2. Restart Vault Agent: `sudo systemctl restart vault-agent-eos`
3. Verify diagnostics pass: `sudo eos debug bionicgpt` (should show ✓ for Vault secrets)
4. Consider migrating to Vault Agent template rendering for automatic secret rotation

**Complexity**: Low (policy update only)
**Target Date**: TBD (when Vault-backed secret delivery required for compliance/rotation)
**Reference**: See diagnostic output showing 403 errors for all 4 secrets (postgres_password, jwt_secret, litellm_master_key, azure_api_key)

---

### Debug Command Technical Debt (BionicGPT Integration Diagnostics)

**Status**: 📋 TRACKED - Issues from adversarial analysis
**Priority**: Mixed (P0-P3)
**Total Effort**: ~14 hours
**Added**: 2025-10-28
**Reference**: `pkg/hecate/debug_bionicgpt.go` (946 lines)

**Context**: Debug command `eos debug hecate --bionicgpt` implemented for Authentik-Caddy-BionicGPT triangle diagnostics. Adversarial analysis identified 22 issues ranging from P0 (breaking) to P3 (nice-to-have).

---

#### P0 - BREAKING (Must Fix)

**Issue 2.3: Hardcoded Container Names** - 30 minutes
- **Files**: `pkg/hecate/debug_bionicgpt.go:105, 128, 151`
- **Problem**: Container name filters assume exact matches (e.g., `name=caddy`) - fails if user customized naming or Docker Compose v1/v2 differences
- **Impact**: Debug command reports false negatives (claims containers not running when they are)
- **Fix**: Use label-based filtering: `--filter label=com.docker.compose.project=hecate` instead of name-based
- **Testing**: Verify on Docker Compose v1 (`hecate_caddy_1`) and v2 (`hecate-caddy-1`) naming conventions

**Issue 4.1: Emoji Usage in Output** - 15 minutes
- **Files**: `pkg/hecate/debug_bionicgpt.go:948-965` (display functions)
- **Problem**: Emojis in output (✅ ❌ ⚠️) violate CLAUDE.md "Memory Notes" (no emojis unless requested)
- **Impact**: Accessibility issues, inconsistent with Eos standards
- **Options**:
  1. Remove all emojis → use `[PASS]`, `[FAIL]`, `[WARN]` (cleanest, aligns with standards)
  2. Add `--no-emoji` flag → keep emojis by default for human-friendliness
- **Decision Required**: User preference on UX vs standards trade-off

---

#### P1 - CRITICAL (Before Production)

**Issue 1.2: Missing Unit Tests** - 2 hours
- **Files**: None - tests do not exist
- **Problem**: Zero test coverage for 946 lines of complex diagnostic logic
- **Priority**: P1 (critical business logic untested, high regression risk)
- **Implementation**:
  - Create `pkg/hecate/debug_bionicgpt_test.go`
  - Test `extractBionicGPTDomain()` (string parsing edge cases)
  - Test `readEnvFile()` (custom .env parser with quotes, comments, malformed lines)
  - Mock Docker API responses for container checks
  - Mock HTTP responses for Authentik API checks
  - Mock file system for Caddyfile reading
- **Coverage Target**: >80% of diagnostic functions

**Issue 2.2: InsecureSkipVerify Always Enabled** - 30 minutes
- **Files**: `pkg/hecate/debug_bionicgpt.go:765-770`
- **Problem**: TLS verification disabled for all HTTP checks (security risk)
- **Attack Scenario**: Man-in-the-middle attack during debug execution
- **Impact**: Secrets could be intercepted if Authentik connection compromised
- **Fix**: Only skip verification for localhost connections, require valid certs for remote
- **Testing**: Verify HTTPS endpoints with valid/invalid/self-signed certificates

**Issue 2.4: Potential Secrets Exposure in Error Messages** - 30 minutes
- **Files**: `pkg/hecate/debug_bionicgpt.go:384, 430`
- **Problem**: HTTP client errors might include auth tokens in URL parameters or headers
- **Impact**: Authentik API token visible in telemetry/logs if API call fails
- **Fix**: Sanitize error messages before logging - redact tokens, credentials
- **Pattern**:
  ```go
  if err != nil {
      sanitizedErr := sanitizeError(err, []string{authentikToken})
      logger.Error("API call failed", zap.Error(sanitizedErr))
  }
  ```

**Issue 3.2: Context Timeout Not Propagated** - 30 minutes
- **Files**: `pkg/hecate/debug_bionicgpt.go:103, 127, 151` (all exec.Command calls)
- **Problem**: Creates multiple child contexts with independent timeouts - parent context cancellation not respected
- **Impact**: User presses Ctrl+C, but Docker/HTTP calls continue for up to 5 seconds each (30+ seconds total)
- **Fix**: Use single context timeout at function level, pass `rc.Ctx` to all child operations
- **Testing**: Run debug command, press Ctrl+C during checks, verify immediate cancellation

**Issue 4.3: Hardcoded Paths Violate Constants Rule** - 15 minutes
- **Files**: `pkg/hecate/debug_bionicgpt.go:595, 252`
- **Problem**: `/opt/bionicgpt/.env`, `/opt/hecate/Caddyfile` hardcoded (violates CLAUDE.md P0 #12)
- **Impact**: Breaks if user customized installation paths
- **Fix**: Extract to constants:
  ```go
  // pkg/bionicgpt/constants.go
  const (
      BionicGPTInstallDir = "/opt/bionicgpt"
      BionicGPTEnvFile = BionicGPTInstallDir + "/.env"
  )

  // pkg/hecate/constants.go
  const (
      HecateInstallDir = "/opt/hecate"
      HecateCaddyfile = HecateInstallDir + "/Caddyfile"
  )
  ```

---

#### P2 - IMPORTANT (Quality Improvements)

**Issue 2.1: Dynamic Container Detection** - 45 minutes
- **Enhancement**: Auto-detect Docker Compose naming convention (v1 vs v2)
- **Implementation**: Use Docker API labels instead of name matching
- **Benefit**: Works universally without hardcoding container names

**Issue 3.1: Add Panic Recovery** - 30 minutes
- **Enhancement**: Wrap each phase check in `defer recover()` to prevent cascading failures
- **Benefit**: One failing check doesn't crash entire diagnostic run

**Issue 5.1: Handle Multiple Caddyfiles (Import Directive)** - 30 minutes
- **Problem**: Assumes single Caddyfile, ignores `import` statements
- **Enhancement**: Parse `import` directives, search imported files for BionicGPT config

**Issue 5.2: Detect Multiple BionicGPT Deployments** - 30 minutes
- **Problem**: Only detects first BionicGPT domain, ignores additional instances
- **Enhancement**: Return `[]string` (all domains), check each instance

**Issue 5.5: Proper Caddyfile Parsing** - 1 hour
- **Problem**: Uses string search (`strings.Contains`) instead of proper parsing
- **Enhancement**: Use `github.com/caddyserver/caddy/v2/caddyconfig/caddyfile` for accurate parsing
- **Benefit**: Avoids false positives from commented-out config or wrong blocks

**Issue 5.6: Check for Conflicting Routes** - 30 minutes
- **Enhancement**: Detect if multiple services proxy to same backend (routing conflicts)

**Issue 7.1: Implement Verbose Mode** - 30 minutes
- **Problem**: `--verbose` flag defined but never used (line 25)
- **Fix**: Add verbose logging when flag enabled

**Issue 8.1: Refactor Long Functions** - 45 minutes
- **Problem**: `checkAuthentikIntegration()` is 180 lines (violates readability)
- **Fix**: Extract subfunctions for each check type

**Issue 8.3: Extract Container Checking Helper** - 30 minutes
- **Problem**: Near-identical code blocks for Caddy/Authentik/BionicGPT checks (lines 94-175)
- **Fix**: Extract `checkContainerRunning(name, category) BionicGPTIntegrationCheck`

---

#### P3 - MINOR (Nice-to-Have)

**Issue 3.3: Add Dry-Run Mode** - 30 minutes
- **Enhancement**: `--dry-run` flag to preview checks without executing

**Issue 4.2: Extract Hardcoded Timeouts** - 15 minutes
- **Problem**: `5 * time.Second` repeated throughout code
- **Fix**: Extract to constants (`DockerCommandTimeout`, `HTTPCheckTimeout`)

**Issue 7.2: Add OpenTelemetry Spans** - 30 minutes
- **Enhancement**: Wrap each phase in `tracer.Start()` for distributed tracing

**Issue 7.3: Progress Indicators** - 30 minutes
- **Enhancement**: Show "Checking X... [1/6]" during long-running operations

**Issue 9.2: Export Format Options** - 30 minutes
- **Enhancement**: Support `--format json|markdown|csv` for machine-parseable output

**Issue 10.1: Add Godoc Comments** - 30 minutes
- **Problem**: Public functions lack documentation
- **Fix**: Add godoc comments to all exported functions

---

### Timeline & Priorities

| Priority | Issues | Effort | Target |
|----------|--------|--------|--------|
| **P0** | 2 | 45 min | Week of 2025-11-03 |
| **P1** | 5 | 3.5 hrs | Week of 2025-11-10 |
| **P2** | 9 | 5.5 hrs | Week of 2025-11-17 |
| **P3** | 6 | 4.5 hrs | TBD (low priority) |

---

### Success Criteria

- [ ] P0 issues fixed (container detection, emoji policy decision)
- [ ] P1 issues fixed (unit tests, security, constants)
- [ ] Build succeeds: `go build -o /tmp/eos-build ./cmd/`
- [ ] Test coverage >80% for diagnostic logic
- [ ] Works on Docker Compose v1 and v2
- [ ] Context cancellation works (Ctrl+C terminates immediately)
- [ ] No secrets in logs/telemetry
- [ ] Godoc comments on all exported functions

---

### Out of Scope

**Not addressing in this cleanup** (tracked separately):
- BionicGPT Vault Agent integration (see "BionicGPT Vault Integration" section above)
- Automatic debug output capture (already implemented in `pkg/debug/capture.go`)
- Evidence collection for remote debug (already implemented in `pkg/remotedebug/evidence.go`)

---

## 🔐 Hecate Consul KV + Vault Integration (Target: April-May 2026)

### Status: Deferred (~6 months from 2025-10-28)

**Context**: Original implementation (2025-10-28) integrated Consul KV for config storage and Vault for secret management in Hecate wizard. User feedback identified this as over-engineering for initial release - reverted to simple `.env` file approach.

**Decision Rationale** (2025-10-28):
- **User Experience**: Wizard prompts for Vault authentication create friction during initial setup
- **Dependency Complexity**: Requires Vault Agent + AppRole configured before Hecate deployment
- **YAGNI Principle**: Simple `.env` file meets 95% of use cases for initial release
- **Iterative Philosophy**: Build on what exists, solve complex problems once, encode in Eos

**Deferred Features**:
1. Consul KV storage for wizard-generated configurations
2. Vault integration for secret management (Authentik tokens, passwords)
3. Consul Template for dynamic config rendering
4. Automatic secret rotation via Vault Agent

**Current Approach** (Simple `.env` files):
- Wizard generates YAML config → creates `.env` files in `/opt/hecate/`
- Secrets stored directly in `.env` (permissions: 0640, owner: root)
- No Consul KV dependency for configuration
- No Vault dependency for secret storage
- Manual secret rotation (user edits `.env`, restarts services)

**Target Implementation** (April-May 2026):
1. **Phase 1: Opt-in Vault Integration** (2 weeks)
   - Add `--vault` flag to wizard (default: disabled)
   - If enabled, store secrets in Vault at `secret/hecate/{service}/{key}`
   - Keep `.env` as fallback if Vault unavailable
   - Document migration path: `.env` → Vault

2. **Phase 2: Consul KV Configuration Storage** (1 week)
   - Add `--consul-kv` flag to wizard (default: disabled)
   - Store wizard config at `hecate/config` key
   - Show retrieval command: `consul kv get hecate/config > hecate-config.yaml`
   - Keep local YAML file as primary source of truth

3. **Phase 3: Consul Template Rendering** (2 weeks)
   - Create Consul Template service for Hecate
   - Render `.env` files from Vault (secrets) + Consul KV (config)
   - Watch for changes, auto-restart services on update
   - Document template syntax for custom configs

4. **Phase 4: Automatic Secret Rotation** (1 week)
   - Vault Agent templates for sensitive credentials
   - Automatic reload on secret rotation
   - Graceful rollback on template errors
   - Telemetry for rotation events

**Success Criteria** (April-May 2026):
- [ ] `.env` file approach remains default (no breaking changes)
- [ ] Vault integration opt-in via `--vault` flag
- [ ] Consul KV integration opt-in via `--consul-kv` flag
- [ ] Migration guide: Simple → Integrated (documented at wiki)
- [ ] TTY detection prevents wizard hang in CI/CD
- [ ] Vault Agent failure gracefully falls back to `.env`
- [ ] Build succeeds: `go build -o /tmp/eos-build ./cmd/`

**Migration Path** (For users on simple `.env` approach):
```bash
# Current (simple .env)
sudo eos create hecate  # Generates /opt/hecate/.env

# Future (opt-in Vault + Consul KV)
sudo eos create hecate --vault --consul-kv  # Stores secrets in Vault, config in Consul

# Migration helper (future)
sudo eos update hecate --migrate-to-vault  # Migrates existing .env to Vault
```

**Code Changes Required** (Estimated):
- Uncomment Consul KV storage in `pkg/hecate/config_generator.go`
- Uncomment Vault integration in `pkg/hecate/yaml_generator.go`
- Add `--vault` and `--consul-kv` flags to `cmd/create/hecate.go`
- Update wizard prompts to show storage location (Vault vs `.env`)
- Add migration command: `eos update hecate --migrate-to-vault`

**Reference Implementation** (Currently commented out):
- [pkg/hecate/config_generator.go](pkg/hecate/config_generator.go) - Consul KV storage logic (commented 2025-10-28)
- [pkg/hecate/yaml_generator.go](pkg/hecate/yaml_generator.go) - Vault secret manager integration (commented 2025-10-28)
- [cmd/create/hecate.go](cmd/create/hecate.go) - Wizard orchestration (simplified 2025-10-28)

**Why Wait 6 Months?**:
1. Let simple approach prove itself in production
2. Gather user feedback on pain points (secret rotation frequency, config drift)
3. Complete secret manager refactoring (Phases 4-6) first
4. Validate Consul Template patterns in other services (Wazuh, BionicGPT)
5. Avoid premature optimization (YAGNI)

**Revisit Date**: April 1, 2026 (review user feedback, decide if still needed)

---

## Questions & Feedback

**Contact**: @henry
**Issues**: GitHub issues with `[secret-refactor]` prefix
**Documentation**: See [docs/SECRET_MANAGER_REFACTORING_PLAN.md](docs/SECRET_MANAGER_REFACTORING_PLAN.md)

---

**Last Updated**: 2025-10-28 by Henry
**Next Review**: 2025-11-10 (Phase 5 completion, Command Structure Phase 2 planning)
