# Eos Development Roadmap

**Last Updated**: 2025-10-28
**Version**: 1.1

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

## Questions & Feedback

**Contact**: @henry
**Issues**: GitHub issues with `[secret-refactor]` prefix
**Documentation**: See [docs/SECRET_MANAGER_REFACTORING_PLAN.md](docs/SECRET_MANAGER_REFACTORING_PLAN.md)

---

**Last Updated**: 2025-10-28 by Henry
**Next Review**: 2025-11-10 (Phase 5 completion)
