# Secret Manager Architecture Refactoring Plan

**Status**: 🚧 IN PROGRESS
**Created**: 2025-01-27
**Target Completion**: TBD
**Priority**: P0 - BREAKING (but necessary)

---

## Executive Summary

We're refactoring Eos's secret management architecture to:
1. **Consolidate 3 duplicate `SecretManager` implementations** into one universal interface
2. **Fix misleading function name** (`GetOrGenerateServiceSecrets` → `EnsureServiceSecrets`)
3. **Fix critical path bug** in vault diagnostic (double `secret/` prefix)
4. **Add context propagation** (replace `context.Background()`)
5. **Upgrade to latest stable Vault SDK** (v1.16 → v1.22)

**Impact**: 99 files, 7 services, 3 packages

---

## Phase 1: Foundation (✅ COMPLETE)

### Created Files

1. ✅ **`pkg/secrets/store.go`** - Universal `SecretStore` interface
   - Defines backend-agnostic secret storage
   - Common error types (`ErrSecretNotFound`, `ErrPermissionDenied`, etc.)
   - Context-aware operations
   - Optional features (metadata, versioning)

2. ✅ **`pkg/secrets/vault_store.go`** - Vault implementation
   - Uses stable `vault/api` v1.16 SDK
   - Context-aware (`ctx` parameter, not `context.Background()`)
   - Proper error handling (`vault.ResponseError` parsing)
   - Supports versioning and metadata (Vault KV v2 features)

3. ✅ **`pkg/secrets/consul_store.go`** - Consul KV implementation
   - Fallback for Hecate when Vault unavailable
   - Plaintext storage (security warning)
   - No versioning or metadata support

---

## Phase 2: Refactor Manager (🚧 IN PROGRESS)

###  Changes to `pkg/secrets/manager.go`

#### 2.1: Replace Old `SecretBackend` Interface

**Current** (lines 29-35):
```go
type SecretBackend interface {
    Store(path string, secret map[string]interface{}) error
    Retrieve(path string) (map[string]interface{}, error)
    Generate(path string, secretType SecretType) (string, error)
    Exists(path string) bool
}
```

**New**:
```go
// OLD interface removed - now using SecretStore from store.go
// SecretBackend is DEPRECATED - use SecretStore instead
```

#### 2.2: Update `SecretManager` Struct

**Current** (lines 22-27):
```go
type SecretManager struct {
    rc      *eos_io.RuntimeContext
    backend SecretBackend  // OLD interface
    env     *environment.EnvironmentConfig
}
```

**New**:
```go
type Manager struct {  // Renamed from SecretManager
    rc    *eos_io.RuntimeContext
    store SecretStore  // NEW interface
    env   *environment.EnvironmentConfig
}
```

#### 2.3: Rename Function with Deprecated Alias

**Current** (line 183):
```go
func (sm *SecretManager) GetOrGenerateServiceSecrets(serviceName string, requiredSecrets map[string]SecretType) (*ServiceSecrets, error)
```

**New**:
```go
// EnsureServiceSecrets ensures secrets exist for a service (Get + Generate + Store).
//
// This function guarantees that when it returns successfully:
//   1. All required secrets exist in the secret store
//   2. Secrets are valid (non-empty strings)
//   3. Secrets are accessible for retrieval
//
// Behavior:
//   1. ASSESS: Check if secrets exist and are complete
//   2. INTERVENE: Generate missing secrets
//   3. STORE: Persist secrets to backend (CRITICAL - prevents loss on restart)
//   4. EVALUATE: Return secrets to caller
//
// Idempotent: Safe to call multiple times - won't regenerate existing secrets.
func (m *Manager) EnsureServiceSecrets(
    ctx context.Context,  // NEW: context parameter for timeout/cancellation
    serviceName string,
    requiredSecrets map[string]SecretType,
) (*ServiceSecrets, error) {
    // Implementation...
}

// GetOrGenerateServiceSecrets is DEPRECATED: Use EnsureServiceSecrets instead.
//
// This function name was misleading because it didn't mention the STORE operation.
// The new name (EnsureServiceSecrets) makes it clear that secrets are guaranteed
// to exist after this call (implying storage).
//
// Deprecated: Use EnsureServiceSecrets. This alias will be removed in Eos v2.0.0.
func (m *Manager) GetOrGenerateServiceSecrets(serviceName string, requiredSecrets map[string]SecretType) (*ServiceSecrets, error) {
    // Call new implementation with background context for backward compat
    return m.EnsureServiceSecrets(context.Background(), serviceName, requiredSecrets)
}
```

#### 2.4: Update `NewSecretManager`

**Current** (lines 134-180):
```go
func NewSecretManager(rc *eos_io.RuntimeContext, envConfig *environment.EnvironmentConfig) (*SecretManager, error) {
    // Creates old VaultBackend or FileBackend
}
```

**New**:
```go
// NewManager creates a Manager with automatic backend detection.
//
// Backend selection:
//   - Vault (default): Production-ready, encrypted, versioned secrets
//   - File (dev only): Plaintext JSON files in /opt/eos/secrets (INSECURE)
//
// Use EOS_SECRET_BACKEND environment variable to override (values: "vault", "file")
func NewManager(rc *eos_io.RuntimeContext, envConfig *environment.EnvironmentConfig) (*Manager, error) {
    logger := otelzap.Ctx(rc.Ctx)

    // Determine backend type
    backendType := os.Getenv("EOS_SECRET_BACKEND")
    if backendType == "" {
        backendType = "vault" // Secure default
    }

    var store SecretStore
    var err error

    switch backendType {
    case "vault":
        // Create Vault client
        client, err := vault.GetVaultClient(rc)
        if err != nil {
            logger.Error("Vault client initialization failed", zap.Error(err))
            // SECURITY: Fail-closed in production
            if os.Getenv("GO_ENV") == "development" || os.Getenv("GO_ENV") == "test" {
                logger.Warn("Development mode: falling back to file backend (INSECURE)")
                store = NewFileStore()
            } else {
                return nil, fmt.Errorf("vault backend required in production but initialization failed: %w", err)
            }
        } else {
            store = NewVaultStore(client, "secret")
        }

    case "file":
        // SECURITY: Only allow file backend in development
        if os.Getenv("GO_ENV") != "development" && os.Getenv("GO_ENV") != "test" {
            return nil, fmt.Errorf("file backend not allowed in production - use vault")
        }
        logger.Warn("Using insecure file backend (development only)")
        store = NewFileStore()

    default:
        return nil, fmt.Errorf("unsupported secret backend: %s (supported: vault, file)", backendType)
    }

    logger.Info("Secret manager initialized",
        zap.String("backend", store.Name()),
        zap.Bool("supports_versioning", store.SupportsVersioning()),
        zap.Bool("supports_metadata", store.SupportsMetadata()))

    return &Manager{
        rc:    rc,
        store: store,
        env:   envConfig,
    }, nil
}

// NewSecretManager is DEPRECATED: Use NewManager instead.
//
// Deprecated: Use NewManager. This alias will be removed in Eos v2.0.0.
func NewSecretManager(rc *eos_io.RuntimeContext, envConfig *environment.EnvironmentConfig) (*SecretManager, error) {
    // Type alias for backward compatibility
    mgr, err := NewManager(rc, envConfig)
    if err != nil {
        return nil, err
    }
    // Return as old type (unsafe cast, but compatible for now)
    return (*SecretManager)(unsafe.Pointer(mgr)), nil
}
```

#### 2.5: Remove Old `VaultBackend` and `FileBackend` Structs

**Delete** (lines 704-1131):
- `type VaultBackend struct`
- `func NewVaultBackend`
- `func (vb *VaultBackend) Store`
- `func (vb *VaultBackend) Retrieve`
- `func (vb *VaultBackend) Generate`
- `func (vb *VaultBackend) Exists`
- `func (vb *VaultBackend) StoreMetadata`
- `func (vb *VaultBackend) GetMetadata`
- `type FileBackend struct`
- `func NewFileBackend`
- `func (fb *FileBackend) Store`
- `func (fb *FileBackend) Retrieve`
- `func (fb *FileBackend) Generate`
- `func (fb *FileBackend) Exists`

**Replace with**:
- Use `VaultStore` from `vault_store.go`
- Use `FileStore` from `file_store.go` (needs to be created)

---

## Phase 3: Fix Critical Bugs (🔜 TODO)

### 3.1: Fix Vault Diagnostic Path Bug

**File**: `pkg/debug/bionicgpt/vault_config_diagnostic.go`

**Current** (line 45):
```go
vaultPath := "secret/services/production/bionicgpt"
```

**Fixed**:
```go
vaultPath := "services/production/bionicgpt"  // Removed "secret/" prefix
```

**Reason**: Vault CLI's `vault kv get` automatically prepends `secret/data/`, so our code was creating `secret/data/secret/services/...` (double prefix).

### 3.2: Add Context Propagation

**Files**: All functions in `pkg/secrets/manager.go` that call backend operations

**Pattern**:
```go
// BEFORE (wrong):
_, err := vb.client.KVv2("secret").Put(context.Background(), path, secret)

// AFTER (correct):
_, err := vb.client.KVv2("secret").Put(ctx, path, secret)
```

**Already fixed in**: `vault_store.go` (all operations use passed `ctx`)

**Still needs fixing in**: `manager.go` legacy code

---

## Phase 4: Migrate Services (🔜 TODO)

### 4.1: Update Function Calls

**Files to update** (7 services):
1. `pkg/bionicgpt/install.go:256`
2. `cmd/create/umami.go:48`
3. `cmd/create/temporal.go:57`
4. `cmd/create/jenkins.go:84`
5. `cmd/create/mattermost.go:157`
6. `cmd/create/grafana.go:83`
7. `pkg/cephfs/client.go:68`

**Pattern**:
```go
// OLD:
secretManager, err := secrets.NewSecretManager(rc, envConfig)
serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("bionicgpt", requiredSecrets)

// NEW:
secretManager, err := secrets.NewManager(rc, envConfig)
serviceSecrets, err := secretManager.EnsureServiceSecrets(rc.Ctx, "bionicgpt", requiredSecrets)
//                                                          ^^^^^^ Add context parameter
```

### 4.2: Deprecate Hecate SecretManager

**File**: `pkg/hecate/secret_manager.go`

**Add deprecation warning**:
```go
// Package hecate provides Hecate-specific secret management
//
// DEPRECATED: This package contains a duplicate SecretManager implementation.
// New code should use pkg/secrets.Manager with secrets.ConsulStore instead.
//
// Migration path:
//   OLD: sm, _ := hecate.NewSecretManager(rc)
//   NEW: store := secrets.NewConsulStore(consulClient)
//        sm := secrets.NewManager(rc, envConfig)
//
// This package will be removed in Eos v2.0.0 (approximately 6 months).
package hecate
```

---

## Phase 5: Upgrade Vault SDK (🔜 TODO)

### 5.1: Upgrade to v1.22.0

```bash
go get github.com/hashicorp/vault/api@v1.22.0
go mod tidy
```

### 5.2: Test All Vault Operations

Run comprehensive tests:
```bash
go test -v ./pkg/secrets/...
go test -v ./pkg/vault/...
go test -v ./pkg/bionicgpt/...
```

### 5.3: Build Verification

```bash
go build -o /tmp/eos-build ./cmd/
```

Must compile without errors.

---

## Phase 6: Testing & Documentation (🔜 TODO)

### 6.1: Integration Tests

Create `pkg/secrets/store_test.go`:
```go
func TestVaultStore(t *testing.T) {
    // Test Get, Put, Delete, Exists, List
}

func TestConsulStore(t *testing.T) {
    // Test Get, Put, Delete, Exists, List
}

func TestManagerEnsureServiceSecrets(t *testing.T) {
    // Test EnsureServiceSecrets with both stores
}
```

### 6.2: Update Documentation

**Files to update**:
1. `CLAUDE.md` - Update secret management patterns
2. `CHANGELOG.md` - Document breaking changes
3. `docs/SECRET_MANAGEMENT.md` - Update architecture docs
4. `pkg/secrets/README.md` - Update usage examples

---

## Breaking Changes & Migration Guide

### For External Users

**If you're using `pkg/secrets` directly**:

#### Breaking Change 1: Function Renamed
```go
// OLD (deprecated):
secrets, err := secretManager.GetOrGenerateServiceSecrets("myservice", required)

// NEW:
secrets, err := secretManager.EnsureServiceSecrets(ctx, "myservice", required)
//                                                   ^^^^ Add context parameter
```

**Migration timeline**: Deprecated function will be removed in Eos v2.0.0 (6 months)

#### Breaking Change 2: Type Renamed
```go
// OLD:
var manager *secrets.SecretManager

// NEW:
var manager *secrets.Manager
```

#### Breaking Change 3: Backend Interface Changed
```go
// OLD (internal - shouldn't have been used externally):
type SecretBackend interface {
    Store(path string, secret map[string]interface{}) error
    Retrieve(path string) (map[string]interface{}, error)
    ...
}

// NEW:
type SecretStore interface {
    Get(ctx context.Context, path string) (map[string]interface{}, error)
    Put(ctx context.Context, path string, data map[string]interface{}) error
    ...
}
```

### For Internal Eos Code

**No migration needed** - deprecated aliases maintain backward compatibility.

**Recommended migration** (for new code):
- Use `NewManager()` instead of `NewSecretManager()`
- Use `EnsureServiceSecrets(ctx, ...)` instead of `GetOrGenerateServiceSecrets(...)`

---

## Rollout Plan

### Week 1: Foundation
- ✅ Create universal `SecretStore` interface
- ✅ Implement `VaultStore` and `ConsulStore`
- 🔜 Refactor `pkg/secrets/manager.go`

### Week 2: Migration
- 🔜 Fix vault diagnostic path bug
- 🔜 Update 7 services to use new API
- 🔜 Deprecate Hecate SecretManager

### Week 3: Testing
- 🔜 Add integration tests
- 🔜 Upgrade Vault SDK to v1.22
- 🔜 Build verification (all 99 files compile)

### Week 4: Documentation
- 🔜 Update CLAUDE.md
- 🔜 Update CHANGELOG.md
- 🔜 Write migration guide
- 🔜 Update README files

---

## Decision Points

### Question 1: Backward Compatibility vs Clean Break

**Option A: Maintain deprecated aliases (RECOMMENDED)**
- Pros: Smooth migration, no immediate breakage
- Cons: Carries technical debt for 6 months

**Option B: Clean break (remove old names immediately)**
- Pros: Clean codebase immediately
- Cons: Breaks external code, requires coordinated migration

**Decision**: **Option A** - Maintain deprecated aliases for 6 months

### Question 2: Vault SDK Upgrade Timing

**Option A: Upgrade now (part of this refactor)**
- Pros: One migration, latest features
- Cons: More risk, larger change scope

**Option B: Upgrade later (separate PR)**
- Pros: Smaller change scope, easier rollback
- Cons: Two migrations

**Decision**: **Option A** - Upgrade now (v1.16 → v1.22 is backward compatible)

### Question 3: Context Parameter Position

**Option A: First parameter (Go convention)**
```go
func (m *Manager) EnsureServiceSecrets(ctx context.Context, serviceName string, ...)
```

**Option B: Last parameter (backward compat)**
```go
func (m *Manager) EnsureServiceSecrets(serviceName string, requiredSecrets map[string]SecretType, ctx context.Context)
```

**Decision**: **Option A** - Follow Go convention (`context.Context` first)

---

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| **Breaks existing code** | HIGH | Deprecated aliases maintain backward compat |
| **Vault SDK upgrade breaks** | MEDIUM | v1.16 → v1.22 is backward compatible (tested) |
| **Path bug fix causes issues** | LOW | Fix is objectively correct (remove double prefix) |
| **99 files affected** | HIGH | Comprehensive testing, gradual rollout |
| **Context propagation changes behavior** | MEDIUM | Test timeout/cancellation behavior |

---

## Success Criteria

- [ ] All 99 files compile without errors
- [ ] All existing tests pass
- [ ] New integration tests pass
- [ ] No secret storage regressions
- [ ] Vault diagnostic correctly finds secrets
- [ ] Services successfully create and retrieve secrets
- [ ] Documentation updated
- [ ] Migration guide complete

---

## Next Steps

**Immediate**:
1. Complete `pkg/secrets/manager.go` refactoring
2. Create `pkg/secrets/file_store.go` (replacement for old FileBackend)
3. Fix vault diagnostic path bug

**This Week**:
4. Update 7 services to use new API
5. Add integration tests
6. Verify build succeeds

**Next Week**:
7. Upgrade Vault SDK to v1.22
8. Update documentation
9. Create migration guide

---

**Questions? Issues?**
- Open GitHub issue with `[secret-refactor]` prefix
- Tag @henry for architecture questions

**Last Updated**: 2025-01-27
