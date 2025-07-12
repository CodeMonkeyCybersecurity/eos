# Eos Migration Guide

This document provides comprehensive guidance for migrating the Eos codebase to follow modern architectural patterns, security best practices, and maintainability standards.

## Table of Contents

1. [Core Principles](#core-principles)
2. [Migration Patterns](#migration-patterns)
3. [Command Structure Migration](#command-structure-migration)
4. [Business Logic Migration](#business-logic-migration)
5. [Clean Architecture Implementation](#clean-architecture-implementation)
6. [Security and Logging Standards](#security-and-logging-standards)
7. [Testing Strategy](#testing-strategy)
8. [Common Examples](#common-examples)
9. [Validation and Quality Assurance](#validation-and-quality-assurance)

## Core Principles

### 1. Separation of Concerns

**Goal**: `cmd/` files should contain ONLY command orchestration. All business logic goes in `pkg/`.

```go
// ❌ BAD: Business logic in cmd/
func runCommand(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Don't implement business logic here
    exec.Command("apt-get", "install", "tool").Run()
    return nil
}

//  GOOD: Command orchestration only
func runCommand(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    config := parseFlags(cmd)
    return toolpkg.Install(rc, config)
}
```

### 2. Assess → Intervene → Evaluate Pattern

Every operation must follow this security-first pattern:

```go
func Operation(rc *eos_io.RuntimeContext, config *Config) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS - Check prerequisites and current state
    logger.Info("Assessing operation prerequisites")
    if err := checkPrerequisites(rc, config); err != nil {
        return fmt.Errorf("prerequisites not met: %w", err)
    }
    
    // INTERVENE - Perform the operation
    logger.Info("Executing operation")
    if err := performOperation(rc, config); err != nil {
        return fmt.Errorf("operation failed: %w", err)
    }
    
    // EVALUATE - Verify success
    logger.Info("Verifying operation results")
    if err := verifyOperation(rc, config); err != nil {
        return fmt.Errorf("verification failed: %w", err)
    }
    
    logger.Info("Operation completed successfully")
    return nil
}
```

### 3. Structured Logging Only

**NEVER** use `fmt.Printf/Println`. Always use structured logging:

```go
// ❌ BAD: Using fmt for output
fmt.Printf("Installing %s...\n", packageName)

//  GOOD: Using structured logging
logger := otelzap.Ctx(rc.Ctx)
logger.Info("Installing package",
    zap.String("package", packageName),
    zap.String("phase", "start"))
```

### 4. RuntimeContext Usage

Always use `*eos_io.RuntimeContext` for:
- Structured logging
- Context cancellation
- Timeout management
- Operation coordination

```go
//  GOOD: Proper RuntimeContext usage
func ProcessData(rc *eos_io.RuntimeContext, data []byte) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Check context cancellation
    select {
    case <-rc.Ctx.Done():
        return fmt.Errorf("processing cancelled: %w", rc.Ctx.Err())
    default:
    }
    
    // Process with timeout awareness
    return doProcessingWithContext(rc.Ctx, data)
}
```

## Migration Patterns

### 1. Command Structure Migration

Transform from function-based to variable-based command definitions:

```go
// ❌ OLD: Function-based command
func NewServiceCmd() *cobra.Command {
    return &cobra.Command{
        Use:   "service",
        Short: "Manage services",
        RunE:  runService,
    }
}

//  NEW: Variable-based command
var serviceCmd = &cobra.Command{
    Use:   "service",
    Short: "Manage services",
    RunE:  eos_cli.Wrap(runService),
}

func init() {
    rootCmd.AddCommand(serviceCmd)
    serviceCmd.Flags().String("config", "", "Configuration file")
}
```

### 2. Flag Variable Migration

Move package-level flag variables to function parameters:

```go
// ❌ OLD: Package-level flag variables
var (
    flagOutputJSON bool
    flagDryRun     bool
)

func init() {
    cmd.Flags().BoolVar(&flagOutputJSON, "json", false, "JSON output")
    cmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "Dry run mode")
}

//  NEW: Parse flags in function
func runCommand(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    outputJSON, _ := cmd.Flags().GetBool("json")
    dryRun, _ := cmd.Flags().GetBool("dry-run")
    
    config := &Config{
        OutputJSON: outputJSON,
        DryRun:     dryRun,
    }
    
    return pkg.Operation(rc, config)
}
```

### 3. Helper Function Migration

Move helper functions from `cmd/` to appropriate `pkg/` packages:

```go
// ❌ OLD: Helper in cmd/
// cmd/create/tool.go
func installTool(toolName string) error {
    return exec.Command("apt-get", "install", toolName).Run()
}

//  NEW: Helper in pkg/
// pkg/toolpkg/install.go
func Install(rc *eos_io.RuntimeContext, config *Config) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS
    logger.Info("Assessing tool installation")
    if installed, err := isInstalled(rc, config.Name); err != nil {
        return fmt.Errorf("failed to check installation: %w", err)
    } else if installed {
        logger.Info("Tool already installed")
        return nil
    }
    
    // INTERVENE
    logger.Info("Installing tool", zap.String("tool", config.Name))
    if err := performInstallation(rc, config); err != nil {
        return fmt.Errorf("installation failed: %w", err)
    }
    
    // EVALUATE
    logger.Info("Verifying installation")
    return verifyInstallation(rc, config)
}
```

## Command Structure Migration

### Verb-First Architecture

Organize commands by action (verb-first), not by noun:

```go
//  GOOD: Verb-first structure
cmd/
├── create/
│   ├── create.go      // Root create command
│   ├── database.go    // eos create database
│   └── vault.go       // eos create vault
├── read/
│   ├── read.go        // Root read command
│   ├── status.go      // eos read status
│   └── config.go      // eos read config
├── update/
│   ├── update.go      // Root update command
│   ├── config.go      // eos update config
│   └── sync.go        // eos update sync
└── delete/
    ├── delete.go      // Root delete command
    └── service.go     // eos delete service
```

### Command Aliases

Use aliases to handle natural language variations:

```go
var updateCmd = &cobra.Command{
    Use:     "update",
    Aliases: []string{"modify", "manage", "sync", "migrate"},
    Short:   "Update system components",
}
```

## Business Logic Migration

### Package Structure

Organize business logic into focused packages:

```go
pkg/
├── [feature]/
│   ├── types.go       // Types, constants, configurations
│   ├── install.go     // Installation logic
│   ├── configure.go   // Configuration logic
│   ├── verify.go      // Verification logic
│   └── *_test.go      // Corresponding test files
```

## Manager Framework Migration

The Eos codebase has 37+ different manager implementations with duplicated patterns. The unified manager framework consolidates them into a consistent, secure, and maintainable pattern.

### Unified Manager Interface

All managers must implement `ResourceManager[T]`:

```go
type ResourceManager[T any] interface {
    // Core CRUD operations
    Create(ctx context.Context, resource T) (*OperationResult, error)
    Read(ctx context.Context, id string) (T, error)
    Update(ctx context.Context, resource T) (*OperationResult, error)
    Delete(ctx context.Context, id string) (*OperationResult, error)
    List(ctx context.Context, options *ListOptions) ([]T, error)

    // Lifecycle management
    Start(ctx context.Context, id string) (*OperationResult, error)
    Stop(ctx context.Context, id string) (*OperationResult, error)
    Restart(ctx context.Context, id string) (*OperationResult, error)

    // Health and status
    GetStatus(ctx context.Context, id string) (*ResourceStatus, error)
    HealthCheck(ctx context.Context, id string) (*HealthCheckResult, error)

    // Validation and configuration
    Validate(ctx context.Context, resource T) error
    Configure(ctx context.Context, id string, config map[string]interface{}) (*OperationResult, error)
}
```

### Manager Migration Steps

1. **Define Resource Type**:
```go
type MyResource struct {
    ID          string                 `json:"id"`
    Name        string                 `json:"name"`
    Config      map[string]interface{} `json:"config"`
    Timestamp   time.Time              `json:"timestamp"`
}
```

2. **Create Manager with BaseManager**:
```go
type MyManager struct {
    *BaseManager
    legacyManager *existing.Manager
}

func NewMyManager(config *ManagerConfig) *MyManager {
    return &MyManager{
        BaseManager:   NewBaseManager("my.manager", config),
        legacyManager: existing.NewManager(),
    }
}
```

3. **Implement Methods with AIE Pattern**:
```go
func (m *MyManager) Create(ctx context.Context, resource MyResource) (*OperationResult, error) {
    start := time.Now()
    
    // ASSESS - Validate inputs
    if err := m.Validate(ctx, resource); err != nil {
        return m.CreateOperationResult(false, "Validation failed", time.Since(start), err), err
    }
    
    // INTERVENE - Perform the operation
    if !m.GetConfig().DryRun {
        if err := m.legacyManager.CreateSomething(resource); err != nil {
            return m.CreateOperationResult(false, "Creation failed", time.Since(start), err), err
        }
    }
    
    // EVALUATE - Verify the result
    if !m.GetConfig().DryRun {
        if err := m.verifyCreation(ctx, resource.ID); err != nil {
            logger.Warn("Creation verification failed", zap.Error(err))
        }
    }
    
    return m.CreateOperationResult(true, "Successfully created", time.Since(start), nil), nil
}
```

4. **Register with Global Registry**:
```go
func init() {
    config := managers.DefaultManagerConfig()
    manager := NewMyManager(config)
    managers.RegisterMyManager("my-service", manager)
}
```

### Manager Migration Priority

1. **Security managers** (highest impact on security)
2. **Database managers** (critical for data integrity)  
3. **Service managers** (high usage)
4. **Container managers** (moderate complexity)
5. **System managers** (lowest risk)

### Interface-Based Design

Define interfaces for testability and flexibility:

```go
// pkg/storage/interfaces.go
type StorageManager interface {
    CreateVolume(rc *eos_io.RuntimeContext, config *VolumeConfig) error
    DeleteVolume(rc *eos_io.RuntimeContext, volumeID string) error
    ListVolumes(rc *eos_io.RuntimeContext) ([]Volume, error)
}

// pkg/storage/manager.go
type Manager struct {
    client StorageClient
    logger *zap.Logger
}

func (m *Manager) CreateVolume(rc *eos_io.RuntimeContext, config *VolumeConfig) error {
    // Implementation with AIE pattern
}
```

## Clean Architecture Implementation

### Domain Layer

Pure business logic with no external dependencies:

```go
// pkg/domain/vault/service.go
type Service struct {
    secretStore   SecretStore     // Interface, not implementation
    auditRepo     AuditRepository // Testable with mocks
    logger        *zap.Logger
}

func (s *Service) GetSecret(ctx context.Context, userID, key string) (*Secret, error) {
    // Pure business logic
    // No external dependencies
    // 100% unit testable
}
```

### Infrastructure Layer

Concrete implementations of domain interfaces:

```go
// pkg/infrastructure/vault/api_secret_store.go
type APISecretStore struct {
    client *api.Client
    logger *zap.Logger
}

func (a *APISecretStore) Get(ctx context.Context, key string) (*Secret, error) {
    // Vault API implementation
    // Error handling and logging
    // Infrastructure concerns
}
```

### Dependency Injection

Wire dependencies through interfaces:

```go
// pkg/vault/factory.go
func NewVaultService(logger *zap.Logger) (*domain.Service, error) {
    // Create infrastructure implementations
    apiStore := infrastructure.NewAPISecretStore(vaultClient, logger)
    fallbackStore := infrastructure.NewFallbackSecretStore(logger)
    compositeStore := infrastructure.NewCompositeSecretStore(apiStore, fallbackStore)
    
    // Create domain service
    return domain.NewService(compositeStore, auditRepo, logger), nil
}
```

## Security and Logging Standards

### Input Validation

Always validate inputs to prevent security issues:

```go
func validateConfig(config *Config) error {
    if config == nil {
        return fmt.Errorf("config cannot be nil")
    }
    
    if strings.Contains(config.Path, "..") {
        return fmt.Errorf("path traversal attempt detected")
    }
    
    if config.Port < 1 || config.Port > 65535 {
        return fmt.Errorf("invalid port: %d", config.Port)
    }
    
    return nil
}
```

### Error Handling

Distinguish between user errors and system errors:

```go
// User errors (exit code 0)
if !fileExists(configPath) {
    return eos_err.NewUserError("config file not found: %s", configPath)
}

// System errors (exit code 1)
if err := writeFile(path, data); err != nil {
    return fmt.Errorf("failed to write file: %w", err)
}
```

### Audit Logging

Log all significant operations:

```go
func (s *Service) DeleteUser(rc *eos_io.RuntimeContext, userID string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Audit log before operation
    logger.Info("Deleting user",
        zap.String("user_id", userID),
        zap.String("operation", "delete_user"),
        zap.String("actor", getCurrentUser(rc)))
    
    // Perform operation
    if err := s.deleteUser(rc, userID); err != nil {
        logger.Error("Failed to delete user",
            zap.String("user_id", userID),
            zap.Error(err))
        return err
    }
    
    // Audit log after operation
    logger.Info("User deleted successfully",
        zap.String("user_id", userID),
        zap.String("operation", "delete_user"))
    
    return nil
}
```

## Testing Strategy

### Unit Tests

Test business logic in isolation:

```go
func TestService_GetSecret(t *testing.T) {
    tests := []struct {
        name     string
        userID   string
        key      string
        mockFn   func(*MockSecretStore)
        wantErr  bool
    }{
        {
            name:   "successful get",
            userID: "user123",
            key:    "api_key",
            mockFn: func(m *MockSecretStore) {
                m.On("Get", mock.Anything, "api_key").Return(&Secret{
                    Key:   "api_key",
                    Value: "secret_value",
                }, nil)
            },
            wantErr: false,
        },
        {
            name:   "secret not found",
            userID: "user123",
            key:    "missing_key",
            mockFn: func(m *MockSecretStore) {
                m.On("Get", mock.Anything, "missing_key").Return(nil, ErrSecretNotFound)
            },
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            mockStore := &MockSecretStore{}
            mockAudit := &MockAuditRepository{}
            tt.mockFn(mockStore)
            
            service := NewService(mockStore, mockAudit, logger)
            
            secret, err := service.GetSecret(context.Background(), tt.userID, tt.key)
            
            if tt.wantErr {
                assert.Error(t, err)
                assert.Nil(t, secret)
            } else {
                assert.NoError(t, err)
                assert.NotNil(t, secret)
                assert.Equal(t, tt.key, secret.Key)
            }
        })
    }
}
```

### Integration Tests

Test complete workflows:

```go
func TestVaultIntegration(t *testing.T) {
    // Skip if vault server not available
    if testing.Short() {
        t.Skip("Skipping integration test in short mode")
    }
    
    // Setup test vault server
    vaultServer := setupTestVault(t)
    defer vaultServer.Close()
    
    // Create service with real infrastructure
    service, err := NewVaultService(logger)
    require.NoError(t, err)
    
    // Test complete workflow
    ctx := context.Background()
    
    // Store secret
    err = service.SetSecret(ctx, "test_user", "test_key", "test_value")
    require.NoError(t, err)
    
    // Retrieve secret
    secret, err := service.GetSecret(ctx, "test_user", "test_key")
    require.NoError(t, err)
    assert.Equal(t, "test_value", secret.Value)
    
    // Delete secret
    err = service.DeleteSecret(ctx, "test_user", "test_key")
    require.NoError(t, err)
    
    // Verify deletion
    _, err = service.GetSecret(ctx, "test_user", "test_key")
    assert.Error(t, err)
}
```

## Common Examples

### Package Migration Example

Before and after comparison for a complete package:

```go
// ❌ BEFORE: pkg/mytool/install.go
package mytool

import (
    "fmt"
    "os/exec"
)

func Install(name string) error {
    fmt.Printf("Installing %s...\n", name)
    return exec.Command("apt-get", "install", name).Run()
}

//  AFTER: pkg/mytool/install.go
package mytool

import (
    "fmt"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
    "github.com/uptrace/opentelemetry-go-extra/otelzap"
    "go.uber.org/zap"
)

func Install(rc *eos_io.RuntimeContext, config *Config) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS - Check prerequisites
    logger.Info("Assessing installation requirements",
        zap.String("tool", config.Name))
    
    if installed, err := isInstalled(rc, config.Name); err != nil {
        return fmt.Errorf("failed to check installation: %w", err)
    } else if installed {
        logger.Info("Tool already installed")
        return nil
    }
    
    // Validate configuration
    if err := validateConfig(config); err != nil {
        return eos_err.NewUserError("invalid configuration: %w", err)
    }
    
    // INTERVENE - Perform installation
    logger.Info("Installing tool", zap.String("tool", config.Name))
    
    output, err := execute.Run(rc.Ctx, execute.Options{
        Command: "apt-get",
        Args:    []string{"install", "-y", config.Name},
        Capture: true,
    })
    
    if err != nil {
        logger.Error("Installation failed",
            zap.String("tool", config.Name),
            zap.Error(err),
            zap.String("output", output))
        return fmt.Errorf("installation failed: %w", err)
    }
    
    // EVALUATE - Verify installation
    logger.Info("Verifying installation")
    
    if err := verifyInstallation(rc, config); err != nil {
        return fmt.Errorf("verification failed: %w", err)
    }
    
    logger.Info("Installation completed successfully",
        zap.String("tool", config.Name))
    
    return nil
}
```

### Service Management Example

Using the eos_unix package for service operations:

```go
func ManageService(rc *eos_io.RuntimeContext, serviceName, action string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // ASSESS - Check service exists
    logger.Info("Checking service status",
        zap.String("service", serviceName),
        zap.String("action", action))
    
    exists, err := eos_unix.SystemctlServiceExists(rc, serviceName)
    if err != nil {
        return fmt.Errorf("failed to check service: %w", err)
    }
    
    if !exists {
        return eos_err.NewUserError("service %s does not exist", serviceName)
    }
    
    // INTERVENE - Perform action
    switch action {
    case "start":
        return eos_unix.SystemctlStart(rc, serviceName)
    case "stop":
        return eos_unix.SystemctlStop(rc, serviceName)
    case "restart":
        return eos_unix.SystemctlRestart(rc, serviceName)
    case "enable":
        return eos_unix.SystemctlEnable(rc, serviceName)
    case "disable":
        return eos_unix.SystemctlDisable(rc, serviceName)
    default:
        return eos_err.NewUserError("invalid action: %s", action)
    }
}
```

## Validation and Quality Assurance

### Pre-Migration Checklist

Before starting any migration:

1. **Read existing code** to understand current functionality
2. **Identify dependencies** and their purposes
3. **Create test plan** for functionality verification
4. **Plan rollback strategy** in case of issues

### Post-Migration Validation

After completing a migration:

```bash
# 1. Compilation check
go build -o /tmp/eos-build ./cmd/

# 2. Linting
golangci-lint run ./pkg/[package]/...

# 3. Unit tests
go test -v ./pkg/[package]/...

# 4. Integration tests
go test -v -tags=integration ./pkg/[package]/...

# 5. Functionality verification
# Test actual commands to ensure they work as expected
```

### Quality Gates

All migrations must pass:

1. **Zero compilation errors**
2. **All existing tests pass**
3. **New tests for migrated code**
4. **Linting without errors**
5. **Functionality preserved**
6. **Performance not degraded**

### Common Pitfalls to Avoid

1. **Don't break existing functionality** - Always maintain backward compatibility
2. **Don't skip error handling** - Wrap errors with context
3. **Don't ignore logging** - Use structured logging everywhere
4. **Don't forget context** - Always pass RuntimeContext
5. **Don't skip tests** - Write tests for all new code
6. **Don't ignore validation** - Validate all inputs
7. **Don't hardcode values** - Use configuration or constants

## Migration Priorities

### High Priority (Core Infrastructure)

1. **Logging Migration** - Replace all `fmt.Printf` with structured logging
2. **Command Structure** - Standardize command patterns
3. **Error Handling** - Implement proper user vs system error distinction
4. **Security Operations** - Apply AIE pattern to security-critical operations

### Medium Priority (Business Logic)

1. **Service Management** - Consolidate systemctl operations
2. **File Operations** - Standardize file handling
3. **Network Operations** - Improve HTTP client usage
4. **Database Operations** - Secure database interactions

### Low Priority (Optimization)

1. **Code Deduplication** - Remove duplicate helper functions
2. **Performance Optimization** - Optimize hot paths
3. **Documentation** - Update documentation to reflect new patterns
4. **Monitoring** - Add comprehensive monitoring

## Success Metrics

A successful migration should achieve:

- **Zero breaking changes** to existing functionality
- **Improved testability** through better separation of concerns
- **Enhanced security** through input validation and audit logging
- **Better maintainability** through clean architecture patterns
- **Reduced complexity** through standardized patterns

## Conclusion

This migration guide provides a comprehensive framework for transforming the Eos codebase into a modern, secure, and maintainable system. By following these patterns and principles, each migration will contribute to the overall improvement of the codebase while maintaining stability and functionality.

The key to successful migration is to:
1. **Start small** - Migrate one component at a time
2. **Test thoroughly** - Verify functionality at each step
3. **Follow patterns** - Use established patterns consistently
4. **Document changes** - Keep documentation up to date
5. **Learn and adapt** - Improve the process based on experience

Remember: The goal is not just to move code around, but to create a more robust, secure, and maintainable system that will serve the project well into the future.