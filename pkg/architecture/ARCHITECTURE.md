# Eos Clean Architecture Proposal

## 🏗️ Layered Architecture Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                       │
│                        cmd/                                 │
├─────────────────────────────────────────────────────────────┤
│                   Application Layer                         │
│                   pkg/application/                          │
│  ┌─────────────────┐ ┌─────────────────┐ ┌────────────────┐ │
│  │  Command Bus    │ │  Query Bus      │ │  Event Bus     │ │
│  └─────────────────┘ └─────────────────┘ └────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                     Domain Layer                            │
│                    pkg/domain/                              │
│  ┌─────────────────┐ ┌─────────────────┐ ┌────────────────┐ │
│  │     Vault       │ │    Infrastructure│ │   Security     │ │
│  │   (Secrets)     │ │   (Servers/Net)  │ │  (Auth/Audit)  │ │
│  └─────────────────┘ └─────────────────┘ └────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                Infrastructure Layer                         │
│                  pkg/infrastructure/                        │
│  ┌─────────────────┐ ┌─────────────────┐ ┌────────────────┐ │
│  │    Providers    │ │    Storage      │ │   External     │ │
│  │ (AWS/Hetzner)   │ │  (DB/Files)     │ │    APIs        │ │
│  └─────────────────┘ └─────────────────┘ └────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Package Organization Principles

### 1. Dependency Direction
- All dependencies point INWARD toward domain
- Domain layer has NO external dependencies
- Infrastructure implements domain interfaces

### 2. Domain Boundaries
```
pkg/domain/
├── vault/           # Secret management domain
│   ├── service.go   # Domain service interfaces
│   ├── entity.go    # Domain entities
│   └── repository.go # Repository interfaces
├── infrastructure/ # Infrastructure management domain
│   ├── server.go    # Server management
│   ├── network.go   # Network configuration
│   └── provider.go  # Cloud provider abstractions
└── security/        # Security and audit domain
    ├── auth.go      # Authentication
    ├── audit.go     # Audit logging
    └── policy.go    # Security policies
```

### 3. Interface-First Design
```go
// Domain defines interfaces
type SecretStore interface {
    Get(ctx context.Context, key string) (*Secret, error)
    Set(ctx context.Context, key string, secret *Secret) error
    Delete(ctx context.Context, key string) error
}

// Infrastructure implements interfaces
type VaultSecretStore struct {
    client *api.Client
}

func (v *VaultSecretStore) Get(ctx context.Context, key string) (*Secret, error) {
    // Implementation details
}
```

## Benefits

1. **Testability**: Each layer can be tested independently
2. **Maintainability**: Clear boundaries reduce coupling
3. **Flexibility**: Implementations can be swapped without domain changes
4. **Scalability**: New features follow established patterns

## Implementation Files

### Core Architecture
- **`interfaces.go`** - Domain interfaces and entities
- **`services.go`** - Business logic and domain services
- **`container.go`** - Dependency injection container

### Examples and Migration
- **`example_implementation.go`** - Concrete implementations showing patterns
- **`migration_guide.go`** - Step-by-step migration strategy

## Quick Start Example

```go
// 1. Create container with dependencies
builder := NewConfigurationBuilder(logger)
container := builder.
    WithSecretStore(vaultSecretStore).
    WithServiceManager(systemdManager).
    WithCommandExecutor(executeCommandExecutor).
    WithAuditRepository(fileAuditRepo).
    MustBuild()

// 2. Get domain service
infraService, _ := container.GetInfrastructureService()

// 3. Use in command handler
status, err := infraService.GetInfrastructureStatus(ctx, userID)
```

## Migration Priority

1. **High Impact**: `pkg/vault` (50+ dependencies) → Extract SecretStore interface
2. **Medium Impact**: `cmd/` packages → Use dependency injection
3. **Low Impact**: Utility packages → Implement domain interfaces

## Testing Strategy

```go
// Before: Hard to test, requires real infrastructure
func TestOldCode(t *testing.T) {
    // Needs actual Vault server, file system, network...
}

// After: Fast unit tests with mocks
func TestNewCode(t *testing.T) {
    mockStore := &MockSecretStore{}
    service := NewSecretService(mockStore, mockAudit, logger)
    // Test business logic in isolation
}
```

## Compatibility

Maintain backward compatibility during migration:
- Keep existing public APIs
- Add new clean architecture APIs alongside
- Gradually migrate internal usage
- Deprecate old APIs with clear migration path

## Files Created

- ✅ `pkg/architecture/interfaces.go` - 155 lines of domain interfaces
- ✅ `pkg/architecture/services.go` - 284 lines of business logic
- ✅ `pkg/architecture/container.go` - 216 lines of dependency injection
- ✅ `pkg/architecture/example_implementation.go` - 312 lines of concrete examples
- ✅ `pkg/architecture/migration_guide.go` - 245 lines of migration strategy