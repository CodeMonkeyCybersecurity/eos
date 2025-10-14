# pkg/vault Consolidation Plan

*Last Updated: 2025-10-14*

## Overview

This document identifies functions and patterns in `pkg/vault` that should be consolidated to follow DRY (Don't Repeat Yourself) principles, reduce code duplication, and simplify maintenance.

**Current Status:**
- **114 Go files** in pkg/vault
- **~1,037+ lines of duplicated code** identified
- **Three separate TLS certificate generation implementations** (now consolidated to one)

---

## Priority 0 (CRITICAL - Already Completed)

### ✅ TLS Certificate Generation
**Status:** COMPLETED

**Consolidation:**
- ✅ Created `tls_certificate.go` - unified certificate generation
- ✅ Updated `install.go` to use `GenerateSelfSignedCertificate()`
- ✅ Updated `phase3_tls_cert.go` to use consolidated module
- ✅ Deprecated duplicate functions in `tls_raft.go`

**Result:**
- **~327 lines of duplicated code eliminated**
- **Single source of truth** for certificate generation
- **Automatic comprehensive SAN enrichment** (hostnames, IPs, wildcards, FQDNs)
- **Consistent security** (4096-bit keys, 10-year validity, proper ExtKeyUsage)

---

## Priority 1 (HIGH - Should Do Next)

### 1. File I/O Operations

**Problem:** File operations duplicated across ~29 files

**Current Duplication:**
```go
// install.go:1301
func (vi *VaultInstaller) createDirectory(path string, mode os.FileMode) error {
    return os.MkdirAll(path, mode)
}

// install.go:1308
func (vi *VaultInstaller) writeFile(path string, content []byte, mode os.FileMode) error {
    return os.WriteFile(path, content, mode)
}

// install.go:1312
func (vi *VaultInstaller) fileExists(path string) bool {
    _, err := os.Stat(path)
    return err == nil
}
```

**Occurrences:**
- `os.MkdirAll`: 42 times across 29 files
- `os.WriteFile`: 101 times across multiple files
- `fileExists` pattern: ~20 implementations

**Recommendation:**
Create `pkg/vault/fileutil/operations.go`:
```go
package fileutil

// EnsureDirectory creates a directory with proper permissions atomically
func EnsureDirectory(path string, mode os.FileMode) error

// WriteFileAtomic writes a file atomically with proper permissions
func WriteFileAtomic(path string, content []byte, mode os.FileMode) error

// Exists checks if a file or directory exists
func Exists(path string) bool

// BackupFile creates a timestamped backup of a file
func BackupFile(path string) error

// SetOwnership sets file ownership to user:group
func SetOwnership(path string, uid, gid int) error
```

**Impact:** ~200 lines eliminated, consistent error handling

---

### 2. User and Ownership Operations

**Problem:** Three different approaches to chown/chmod operations

**Current Duplication:**
```go
// install.go uses syscall.Chown for atomicity
if err := syscall.Chown(dir.path, uid, gid); err != nil {
    return fmt.Errorf("failed to set ownership: %w", err)
}

// phase3_tls_cert.go uses eos_unix
uid, gid, err := eos_unix.LookupUser(rc.Ctx, "vault")
if err := eos_unix.ChownR(rc.Ctx, p, uid, gid); err != nil {
    // handle error
}

// tls_raft.go has TODO placeholder
func setVaultOwnership(certPath, keyPath string) error {
    // TODO: Implement proper ownership setting
    return nil
}
```

**Occurrences:**
- `os.Chown`: ~60 times
- `os.Chmod`: ~60 times
- User lookup: ~15 implementations

**Recommendation:**
Create `pkg/vault/ownership/manager.go`:
```go
package ownership

type OwnershipManager struct {
    defaultUser  string
    defaultGroup string
    rc           *eos_io.RuntimeContext
}

// SetVaultOwnership sets ownership to vault:vault with proper error handling
func (om *OwnershipManager) SetVaultOwnership(paths ...string) error

// SetOwnershipRecursive recursively sets ownership
func (om *OwnershipManager) SetOwnershipRecursive(path string, uid, gid int) error

// LookupVaultUser looks up the vault user (cached)
func (om *OwnershipManager) LookupVaultUser() (uid, gid int, err error)

// EnsurePermissions sets both ownership and permissions atomically
func (om *OwnershipManager) EnsurePermissions(path string, mode os.FileMode) error
```

**Impact:** ~150 lines eliminated, consistent ownership model

---

### 3. Network Operations

**Problem:** Port checking and health probes scattered across files

**Current Duplication:**
```go
// install.go:1275
func (vi *VaultInstaller) checkPortAvailable(port int) error {
    output, err := vi.runner.RunOutput("sh", "-c",
        fmt.Sprintf("lsof -i :%d 2>/dev/null | grep LISTEN ...", port))
    // ... complex parsing logic
}

// Different implementations in:
// - installer_helpers.go (ValidationHelper.CheckPort)
// - phase5_start_service.go (waitForVaultHealth)
// - Multiple health check functions
```

**Occurrences:**
- Port checking: 3+ implementations
- Health checks: 5+ implementations
- HTTP probes: scattered throughout

**Recommendation:**
Create `pkg/vault/network/operations.go`:
```go
package network

// IsPortAvailable checks if a port is available for binding
func IsPortAvailable(port int) (bool, error)

// IsPortListening checks if a port is currently listening
func IsPortListening(port int) (bool, string, error) // returns process name

// WaitForPort waits for a port to start listening with timeout
func WaitForPort(port int, timeout time.Duration) error

// ProbeHTTP probes an HTTP endpoint with retries
func ProbeHTTP(url string, expectedStatus int, timeout time.Duration) error

// WaitForVaultHealth waits for Vault to be healthy
func WaitForVaultHealth(addr string, timeout time.Duration) error
```

**Impact:** ~50 lines eliminated, consistent network checks

---

### 4. Systemd Service Management

**Problem:** Systemd operations partially abstracted but duplicated in critical areas

**Current State:**
- `installer_helpers.go`: SystemdService abstraction exists
- `install.go`: Creates vault.service directly (lines 862-1036)
- `phase5_start_service.go`: Writes systemd unit (lines 48-135)

**Recommendation:**
Consolidate into `pkg/vault/systemd/service.go`:
```go
package systemd

type ServiceManager struct {
    runner *CommandRunner
    unit   *UnitFile
}

// UnitFile represents a systemd unit configuration
type UnitFile struct {
    Description string
    User        string
    Group       string
    ExecStart   string
    // ... other fields
}

// WriteUnitFile writes a systemd unit file from template
func (sm *ServiceManager) WriteUnitFile(service string, config *UnitFile) error

// Reload reloads systemd daemon
func (sm *ServiceManager) Reload() error

// EnableAndStart enables and starts a service atomically
func (sm *ServiceManager) EnableAndStart(service string) error

// GetStatus returns detailed service status
func (sm *ServiceManager) GetStatus(service string) (*ServiceStatus, error)
```

**Files to Update:**
- `install.go`: Use ServiceManager instead of direct commands
- `phase5_start_service.go`: Use ServiceManager
- Remove duplication, keep `installer_helpers.go` SystemdService

**Impact:** ~150 lines eliminated, consistent systemd handling

---

### 5. Vault Configuration Generation

**Problem:** Two separate configuration systems

**Current State:**
```go
// install.go:710-859 (150 lines)
func (vi *VaultInstaller) configure() error {
    // Generates storage config, seal config, listener config inline
    var storageConfig string
    switch vi.config.StorageBackend {
    case "consul": storageConfig = `storage "consul" { ... }`
    case "raft": storageConfig = fmt.Sprintf(`storage "raft" { ... }`)
    }
    // ... more inline generation
}

// phase4_config.go:118-171
func WriteVaultHCL(rc *eos_io.RuntimeContext) error {
    params := shared.VaultConfigParams{...}
    hcl, err := shared.RenderVaultConfigRaft(params)
    // ... uses templates
}
```

**Recommendation:**
Consolidate into `pkg/vault/config/generator.go`:
```go
package config

type Generator struct {
    params *GeneratorParams
}

type GeneratorParams struct {
    StorageBackend  string
    NodeID          string
    APIAddr         string
    ClusterAddr     string
    DataPath        string
    TLSEnabled      bool
    TLSCertPath     string
    TLSKeyPath      string
    AutoUnseal      *AutoUnsealConfig
    RetryJoinNodes  []RetryJoinNode
}

// GenerateVaultHCL generates complete vault.hcl from parameters
func (g *Generator) GenerateVaultHCL() (string, error)

// GenerateStorageConfig generates storage backend configuration
func (g *Generator) GenerateStorageConfig() (string, error)

// GenerateSealConfig generates seal configuration (shamir or auto-unseal)
func (g *Generator) GenerateSealConfig() (string, error)

// GenerateListenerConfig generates listener configuration
func (g *Generator) GenerateListenerConfig() (string, error)

// Validate validates the generated configuration
func (g *Generator) Validate() error
```

**Files to Update:**
- `install.go`: Remove inline config generation, use Generator
- `phase4_config.go`: Use Generator
- Consolidate templates into single location

**Impact:** ~200 lines eliminated, consistent config generation

---

## Priority 2 (MEDIUM - Nice to Have)

### 6. Command Execution Abstraction

**Problem:** CommandRunner exists but not used consistently

**Current State:**
- `installer_helpers.go`: CommandRunner abstraction (lines 20-132)
- Many files use `exec.Command()` directly
- Inconsistent error handling and output capture

**Recommendation:**
Enhance and enforce use of existing CommandRunner:
```go
// In installer_helpers.go, add:

// RunWithContext runs a command with context cancellation
func (cr *CommandRunner) RunWithContext(ctx context.Context, cmd string, args ...string) error

// RunOutputWithContext runs and captures output with context
func (cr *CommandRunner) RunOutputWithContext(ctx context.Context, cmd string, args ...string) (string, error)

// RunJSON runs a command and parses JSON output
func (cr *CommandRunner) RunJSON(cmd string, args ...string, result interface{}) error

// MustRun runs a command and panics on error (for init/setup code)
func (cr *CommandRunner) MustRun(cmd string, args ...string)
```

**Enforcement:**
- Add linting rule to prevent direct `exec.Command()` usage
- Update all direct exec.Command calls to use CommandRunner

**Impact:** ~100 lines cleaner, consistent command execution

---

### 7. Vault Client Initialization

**Problem:** Multiple patterns for creating Vault API clients

**Current Files:**
- `client.go`: Main client implementation
- `client_management.go`: Client lifecycle
- `client_context.go`: Context management
- Many files create clients directly

**Recommendation:**
Create `pkg/vault/client/factory.go`:
```go
package client

type ClientFactory struct {
    defaultAddr    string
    defaultTimeout time.Duration
    tlsConfig      *tls.Config
}

// NewClient creates a Vault client with sensible defaults
func (cf *ClientFactory) NewClient() (*api.Client, error)

// NewClientWithToken creates an authenticated client
func (cf *ClientFactory) NewClientWithToken(token string) (*api.Client, error)

// NewClientFromEnv creates a client from environment variables
func (cf *ClientFactory) NewClientFromEnv() (*api.Client, error)

// WaitForReady waits for Vault to be ready and returns a client
func (cf *ClientFactory) WaitForReady(timeout time.Duration) (*api.Client, error)
```

**Impact:** ~80 lines eliminated, consistent client creation

---

### 8. Error Handling Patterns

**Problem:** Inconsistent error wrapping and context

**Current State:**
- Some files use `fmt.Errorf("... : %w", err)`
- Some use `cerr.Wrap(err, "...")`
- Some use `errors.New()`
- Inconsistent error context

**Recommendation:**
Create `pkg/vault/errors/types.go`:
```go
package errors

// Standard error types
type InstallationError struct { ... }
type ConfigurationError struct { ... }
type NetworkError struct { ... }
type PermissionError struct { ... }

// Wrap adds context to an error
func Wrap(err error, message string) error

// Wrapf adds formatted context to an error
func Wrapf(err error, format string, args ...interface{}) error

// IsRetryable determines if an error should trigger a retry
func IsRetryable(err error) bool

// NewUserError creates a user-facing error (exit 0)
func NewUserError(message string) error

// NewSystemError creates a system error (exit 1)
func NewSystemError(message string) error
```

**Impact:** Consistent error handling, better debugging

---

### 9. Logging Helpers

**Problem:** Repetitive logging patterns

**Current State:**
```go
// Repeated pattern across many files:
log := otelzap.Ctx(rc.Ctx)
log.Info("Starting X", zap.String("path", path), zap.Int("count", count))
```

**Recommendation:**
Create `pkg/vault/logging/helpers.go`:
```go
package logging

// LogOperation logs the start and end of an operation
func LogOperation(rc *eos_io.RuntimeContext, operation string, fields ...zap.Field) func(error)

// Usage:
// defer logging.LogOperation(rc, "generate_certificate", zap.String("path", path))()

// LogProgress logs incremental progress
func LogProgress(rc *eos_io.RuntimeContext, current, total int, operation string)

// LogWithDuration logs with elapsed time
func LogWithDuration(rc *eos_io.RuntimeContext, operation string, fields ...zap.Field) func()
```

**Impact:** Cleaner code, consistent logging patterns

---

### 10. Directory Structure Helpers

**Problem:** Directory creation patterns repeated

**Current State:**
- Creating `/etc/vault.d`, `/opt/vault/data`, etc. duplicated
- Permission setting duplicated
- Ownership setting duplicated

**Recommendation:**
Create `pkg/vault/directories/manager.go`:
```go
package directories

type DirectoryLayout struct {
    ConfigDir string // /etc/vault.d
    DataDir   string // /opt/vault/data
    TLSDir    string // /etc/vault.d/tls
    LogDir    string // /var/log/vault
}

type DirectoryManager struct {
    layout *DirectoryLayout
    owner  string
    group  string
}

// EnsureLayout creates all required directories with proper permissions
func (dm *DirectoryManager) EnsureLayout() error

// CleanLayout removes all Vault directories (for uninstall)
func (dm *DirectoryManager) CleanLayout() error

// VerifyLayout checks that all directories exist and have proper permissions
func (dm *DirectoryManager) VerifyLayout() error
```

**Impact:** ~100 lines eliminated, consistent directory structure

---

## Priority 3 (LOW - Future Improvement)

### 11. Testing Helpers

**Problem:** Test setup code duplicated

**Recommendation:**
Create `pkg/vault/testing/fixtures.go` with common test helpers

### 12. Constants Consolidation

**Problem:** Magic numbers and strings scattered

**Recommendation:**
Audit and consolidate into `constants.go` or appropriate subpackages

### 13. Validation Helpers

**Problem:** Input validation patterns repeated

**Recommendation:**
Create `pkg/vault/validation/` package for common validations

---

## Implementation Strategy

### Phase 1: Critical (Week 1)
1. ✅ TLS Certificate Generation (COMPLETED)
2. File I/O Operations
3. User/Ownership Operations
4. Network Operations

### Phase 2: Important (Week 2)
5. Systemd Service Management
6. Vault Configuration Generation
7. Command Execution Standardization

### Phase 3: Cleanup (Week 3)
8. Vault Client Initialization
9. Error Handling Patterns
10. Directory Structure Helpers

### Phase 4: Polish (Week 4)
11. Logging Helpers
12. Testing Helpers
13. Constants/Validation

---

## Success Metrics

**Before:**
- 114 files
- ~15,000+ total lines
- ~1,037+ lines of duplication
- 3 TLS implementations
- Inconsistent patterns

**Target After Full Consolidation:**
- ~100-105 files (remove 9-14 files via consolidation)
- ~13,500 total lines (10% reduction)
- <100 lines of acceptable duplication
- 1 unified approach for each operation type
- Consistent patterns enforced by linting

**Estimated Savings:**
- **~1,500 lines of code eliminated**
- **50% reduction in duplicated patterns**
- **30% easier to maintain**
- **Better testability** through clear interfaces

---

## Next Steps

1. Review and approve this consolidation plan
2. Create feature branch: `refactor/vault-dry-consolidation`
3. Implement Priority 1 items (File I/O, Ownership, Network)
4. Update all call sites to use consolidated functions
5. Add linting rules to prevent future duplication
6. Document new patterns in `PATTERNS.md`

---

*This consolidation follows the principle: "Solve complex problems once, encode in Eos, never solve again."*
