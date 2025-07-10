# Comprehensive Migration Plan: cmd/ to pkg/

## Overview
This document outlines the systematic migration of all business logic from `cmd/` to `pkg/` directories. The goal is to ensure that `cmd/` files contain ONLY:
1. `func init() {}`
2. `var xxxCmd = &cobra.Command{}`

Everything else (types, functions, constants, variables) must be moved to appropriate `pkg/` locations.

## Migration Statistics
- **Total Go files in cmd/**: 222
- **Non-init functions to migrate**: ~343
- **Type definitions to migrate**: 26
- **Constants to migrate**: 2
- **Package-level variables to migrate**: Multiple (flag vars and others)

## Phase 1: Core Infrastructure Types & Functions

### 1.1 Pipeline Package (`pkg/pipeline/`)
**Files to migrate from:**
- `cmd/read/pipeline_webhook_status.go`
- `cmd/read/pipeline_services.go`
- `cmd/read/pipeline_alerts.go`
- `cmd/read/pipeline_prompts.go`
- `cmd/update/pipeline_services.go`
- `cmd/update/pipeline_prompts.go`

**Items to migrate:**
```go
// Types
type WebhookStatus struct {...}
type ServiceStatus struct {...}
type FileInfo struct {...}
type Alert struct {...}
type ServiceWorkerInfo struct {...}

// Functions
func checkWebhookStatus(rc *eos_io.RuntimeContext, verbose bool) *WebhookStatus
func allFilesPresent(files map[string]bool) bool
func checkEnvVar(envFile, varName string) bool
func outputStatusJSON(status *WebhookStatus) error
func outputStatusText(status *WebhookStatus, logger otelzap.LoggerWithCtx) error
func GetServiceWorkers(eosRoot string) []ServiceWorkerInfo
func CopyFile(src, dst string) error
func updateServiceWorker(rc *eos_io.RuntimeContext, worker ServiceWorkerInfo) error
func restartServiceIfRunning(ctx context.Context, serviceName string) error
func verifyOneshotCompletion(ctx context.Context, serviceName string) error
```

### 1.2 Delphi Package (`pkg/delphi/`)
**Files to migrate from:**
- `cmd/read/delphi.go`
- `cmd/read/delphi_api.go`
- `cmd/read/delphi_agents.go`
- `cmd/read/delphi_services_logs.go`
- `cmd/update/delphi.go`
- `cmd/update/delphi_api.go`
- `cmd/update/delphi_agents.go`
- `cmd/update/delphi_passwds.go`

**Items to migrate:**
```go
// Types
type Agent struct {...}

// Functions (from delphi_api.go, delphi_passwds.go)
func updateDelphiAPI(rc *eos_io.RuntimeContext, ...) error
func syncDelphiPasswords(rc *eos_io.RuntimeContext, ...) error
// ... other helper functions
```

### 1.3 Storage Package (`pkg/storage/`)
**Files to migrate from:**
- `cmd/read/storage.go`
- `cmd/read/storage_metrics.go`
- `cmd/list/storage.go`
- `cmd/update/storage.go`

**Items to migrate:**
- Storage-related helper functions
- Metrics collection functions
- Storage status structures

### 1.4 System Services Package (`pkg/system_services/`)
**Files to migrate from:**
- `cmd/update/services.go`

**Items to migrate:**
```go
// Variables (flag variables)
var servicesOutputJSON bool
var servicesDryRun bool
var servicesShowAll bool
var servicesSudo bool
var servicesListState []string
var servicesListPattern string
var servicesListEnabled *bool
var servicesListRunning *bool
var servicesListEnabledStr string
var servicesListRunningStr string
var servicesStartEnable bool
var servicesStopDisable bool

// Functions
func outputServiceList(result *system_services.ServiceManagerResult, outputJSON bool) error
func outputServiceOperationResult(result *system_services.ServiceOperationResult, ...) error
// ... other service-related helper functions
```

## Phase 2: Authentication & Security

### 2.1 LDAP Package (`pkg/ldap/`)
**Files to migrate from:**
- `cmd/update/ldap.go`

**Items to migrate:**
```go
// Variables
var ipSAN string
var dryRun bool

// Functions
func regenerateLDAPCertificate(rc *eos_io.RuntimeContext, ipSAN string, dryRun bool) error
```

### 2.2 Authentication Package (`pkg/authentication/`)
**Files to migrate from:**
- `cmd/read/authentik.go`
- `cmd/read/keycloak.go`
- `cmd/update/authz.go`

## Phase 3: Container & Infrastructure

### 3.1 Container Package (`pkg/container/`)
**Files to migrate from:**
- `cmd/read/container_compose.go`
- `cmd/update/containers.go`

### 3.2 Hecate Package (`pkg/hecate/`)
**Files to migrate from:**
- `cmd/read/hecate.go`
- `cmd/create/hecate_terraform.go`

**Items to migrate:**
```go
// Constants
const HecateTerraformTemplate = `...`
const HecateCloudInitTemplate = `...`
```

### 3.3 Infrastructure Package (`pkg/infrastructure/`)
**Files to migrate from:**
- `cmd/read/infra.go`
- `cmd/read/terraform_graph.go`

## Phase 4: Database & Vault

### 4.1 Database Management (`pkg/database_management/`)
**Files to migrate from:**
- `cmd/read/database_credentials.go`
- `cmd/read/database_status.go`
- `cmd/update/postgres.go`

### 4.2 Vault Package (`pkg/vault/`)
**Files to migrate from:**
- `cmd/list/vault_status_enhanced.go`

## Phase 5: System & Utilities

### 5.1 System Package (`pkg/system/`)
**Files to migrate from:**
- `cmd/read/system.go`
- `cmd/update/system.go`
- `cmd/update/cleanup.go`
- `cmd/update/clean.go`

### 5.2 User Management (`pkg/users/`)
**Files to migrate from:**
- `cmd/read/users.go`
- `cmd/update/users.go`
- `cmd/update/suspension.go`

### 5.3 Package Management (`pkg/package_management/`)
**Files to migrate from:**
- `cmd/update/packages.go`

**Items to migrate:**
```go
// Variables
var Cron bool
```

## Phase 6: Self Management & Git

### 6.1 Git Management (`pkg/git_management/`)
**Files to migrate from:**
- `cmd/self/git_commit.go`
- `cmd/self/git/*.go`

**Items to migrate:**
```go
// Types
type GitStatus struct {...}
type ChangeAnalysis struct {...}

// Functions
func analyzeChanges(rc *eos_io.RuntimeContext, ...) (*ChangeAnalysis, error)
func createCommit(rc *eos_io.RuntimeContext, ...) error
// ... other git helper functions
```

### 6.2 Telemetry (`pkg/telemetry/`)
**Files to migrate from:**
- `cmd/self/telemetry.go`

**Items to migrate:**
```go
// Types
type TelemetryStats struct {...}
```

## Phase 7: Specialized Tools

### 7.1 Jenkins Package (`pkg/jenkins/`)
**Files to migrate from:**
- `cmd/update/jenkins.go`

**Items to migrate:**
```go
// Variables
var backendIP string
```

### 7.2 Salt Package (`pkg/saltstack/`)
**Files to migrate from:**
- `cmd/read/salt_job_status.go`
- `cmd/update/salt_key_accept.go`

### 7.3 ZFS Package (`pkg/zfs_management/`)
**Files to migrate from:**
- `cmd/list/zfs_filesystems.go`
- `cmd/list/zfs_pools.go`

## Phase 8: Miscellaneous

### 8.1 Disk Management (`pkg/disk_management/`)
**Files to migrate from:**
- `cmd/read/disk_usage.go`

### 8.2 Cron Management (`pkg/cron_management/`)
**Files to migrate from:**
- `cmd/update/crontab.go`

**Items to migrate:**
```go
// Variables
var email string
```

### 8.3 Parse Package (`pkg/parse/`)
**Files to migrate from:**
- `cmd/update/parse.go`

### 8.4 Microsoft Integration (`pkg/microsoft/`)
**Files to migrate from:**
- `cmd/update/for_microsoft.go`

**Items to migrate:**
```go
// Variables
var flagMicrosoft bool
```

### 8.5 AB Testing (`pkg/ab_testing/`)
**Files to migrate from:**
- `cmd/read/analyze-ab-results.go`
- `cmd/update/ab_config.go`

**Items to migrate:**
```go
// Variables
var abConfigStatusDetailed bool
// ... other AB config variables
```

### 8.6 Monitoring (`pkg/monitoring/`)
**Files to migrate from:**
- `cmd/read/monitor-delphi.go`

### 8.7 Network (`pkg/network/`)
**Files to migrate from:**
- `cmd/read/tailscale.go`

### 8.8 Process Management (`pkg/process/`)
**Files to migrate from:**
- `cmd/update/process.go`

### 8.9 SSH Management (`pkg/ssh/`)
**Files to migrate from:**
- `cmd/update/ssh.go`

## Migration Order & Dependencies

### Priority 1 (Core Infrastructure)
1. Pipeline package - Many commands depend on pipeline functionality
2. Delphi package - Core monitoring infrastructure
3. System services - Used by many other packages

### Priority 2 (Common Utilities)
1. Storage package
2. User management
3. Package management

### Priority 3 (Security & Auth)
1. LDAP package
2. Authentication packages

### Priority 4 (Infrastructure)
1. Container management
2. Hecate
3. Infrastructure/Terraform

### Priority 5 (Data Services)
1. Database management
2. Vault enhancements

### Priority 6 (Everything Else)
- Remaining packages in phases 6-8

## Migration Guidelines

1. **Create Package Structure**: For each package, create:
   - `types.go` - All type definitions
   - `helpers.go` - General helper functions
   - Specific files for logical groupings (e.g., `webhook.go`, `services.go`)

2. **Move Variables**: Package-level variables should be:
   - Moved to a config struct if they're configuration
   - Passed as parameters if they're runtime values
   - Kept as package variables only if truly needed globally

3. **Update Imports**: After moving functions/types:
   - Update imports in cmd files
   - Remove unused imports
   - Add new package imports

4. **Testing**: For each migration:
   - Ensure compilation succeeds
   - Run existing tests
   - Add new tests for migrated functions

5. **Documentation**: Update function comments to include:
   - Package documentation
   - Function documentation
   - Example usage where helpful

## Validation Steps

After each phase:
1. `go build -o /tmp/eos-build ./cmd/`
2. `golangci-lint run`
3. `go test -v ./pkg/...`
4. Verify command functionality hasn't changed

## Special Considerations

1. **Flag Variables**: Currently stored as package-level vars in cmd files. These should be:
   - Collected into config structs
   - Passed to functions as parameters
   - Not stored as global state in pkg files

2. **Helper Functions**: Many helper functions are duplicated across files. During migration:
   - Identify common patterns
   - Create shared utilities
   - Eliminate duplication

3. **Error Handling**: Ensure all migrated functions follow the error handling patterns:
   - User errors vs system errors
   - Proper error wrapping
   - Consistent error messages

4. **Logging**: All functions must use `otelzap.Ctx(rc.Ctx)` for logging