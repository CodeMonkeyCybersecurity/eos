# Authentik Client Consolidation Migration Guide

**Status**: IN PROGRESS (P0 #2)
**Date**: 2025-10-30

## Background

We had **three separate Authentik HTTP clients**:
1. `pkg/authentik/client.go` - `APIClient` (general API calls)
2. `pkg/authentik/authentik_client.go` - `AuthentikClient` (user/group management)
3. `pkg/hecate/authentik/export.go` - `AuthentikClient` (export functionality)

This created code duplication, inconsistent retry logic, and maintenance burden.

## Solution

**Unified Client**: `pkg/authentik/unified_client.go` consolidates all three into a single `Client` struct.

### Features
- ✅ TLS 1.2 enforcement (from `client.go`)
- ✅ Exponential backoff retry (from `pkg/hecate/authentik/export.go`)
- ✅ Proper error handling with context
- ✅ Consistent API surface

## Completed Steps

1. ✅ Created `pkg/authentik/unified_client.go` - Base HTTP client with retry logic
2. ✅ Created `pkg/authentik/users.go` - User/Group/Event management methods

## Migration Path (TODO)

### Phase 1: Create Wrapper Functions (Backward Compatibility)

```go
// pkg/authentik/compat.go
// Temporary compatibility layer during migration

// NewClient wraps NewUnifiedClient for backward compatibility
func NewClient(baseURL, token string) *APIClient {
    unified := NewUnifiedClient(baseURL, token)
    return &APIClient{unified: unified}
}

// NewAuthentikClient wraps NewUnifiedClient for backward compatibility
func NewAuthentikClient(baseURL, token string) (*AuthentikClient, error) {
    unified := NewUnifiedClient(baseURL, token)
    return &AuthentikClient{unified: unified}, nil
}
```

### Phase 2: Update All Imports (40+ files)

**Files to Update**:
```
pkg/authentik/brand.go
pkg/authentik/provider.go
pkg/authentik/application.go
pkg/authentik/flows.go
pkg/authentik/groups.go
pkg/authentik/outpost.go
pkg/authentik/proxy_provider.go
pkg/authentik/saml.go
pkg/authentik/stages.go
pkg/authentik/extract.go
pkg/authentik/import.go
pkg/authentik/debug.go
pkg/authentik/wazuh.go
pkg/hecate/auth.go
pkg/hecate/auth_manager.go
pkg/hecate/auth_complete.go
(and 25+ more files)
```

**Pattern**:
```go
// OLD
import "github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
client := authentik.NewClient(baseURL, token)

// NEW
import "github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
client := authentik.NewUnifiedClient(baseURL, token)
```

### Phase 3: Migrate pkg/hecate/authentik/ to pkg/authentik/

**Move these files**:
- `pkg/hecate/authentik/export.go` → `pkg/authentik/export.go`
- `pkg/hecate/authentik/drift.go` → `pkg/authentik/drift.go`
- `pkg/hecate/authentik/validation.go` → `pkg/authentik/validation.go`
- `pkg/hecate/authentik/interfaces.go` → `pkg/authentik/interfaces.go` (optional)

**Update imports**:
```go
// OLD
import "github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/authentik"

// NEW
import "github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
```

### Phase 4: Update Export to Use Unified Client

```go
// pkg/authentik/export.go

// OLD
type AuthentikClient struct {
    BaseURL    string
    Token      string
    HTTPClient *http.Client
}

// NEW - just use the unified Client directly
func ExportAuthentikConfig(rc *eos_io.RuntimeContext) error {
    client := NewUnifiedClient(baseURL, token)

    // Use client.Get(), client.Post(), etc.
    data, err := client.Get(rc.Ctx, "/core/applications/")
    // ...
}
```

### Phase 5: Remove Old Client Files

After all migrations complete:
```bash
rm pkg/authentik/client.go
rm pkg/authentik/authentik_client.go
rm -rf pkg/hecate/authentik/
```

### Phase 6: Update cmd/ Imports

```go
// cmd/update/authentik.go
// OLD
import "github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/authentik"

// NEW
import "github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
```

## Testing Checklist

After each phase:
- [ ] `go build -o /tmp/eos-build ./cmd/`
- [ ] `go test -v ./pkg/authentik/...`
- [ ] `eos update authentik --export` (test export still works)
- [ ] `eos update hecate --add bionicgpt` (test Hecate integration)

## Rollback Plan

If migration causes issues:
1. Revert commits
2. Keep old clients alongside new unified client
3. Gradually migrate on a per-file basis

## Timeline

- **Week 1**: Phases 1-2 (backward compatibility + selective migration)
- **Week 2**: Phase 3 (move export to pkg/authentik)
- **Week 3**: Phases 4-6 (complete migration + cleanup)
- **Week 4**: Testing + documentation

## Notes

- **DO NOT** delete old client files until ALL imports updated
- **DO** keep backward compatibility wrappers during migration
- **DO** test after each file migration
- **DO** update tests alongside code migration

## Related

- See P1 #3 for Blueprint migration (separate but related)
- See P1 #5 for database backup (uses unified client)
