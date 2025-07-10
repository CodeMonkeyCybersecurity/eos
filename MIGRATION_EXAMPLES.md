# Migration Examples: Specific Items to Move

This document provides specific examples of items that need to be migrated from `cmd/` to `pkg/`.

## Example 1: Pipeline Services (cmd/update/pipeline_services.go)

### Items to Migrate:
```go
// Type definition (lines 20-25)
type ServiceWorkerInfo struct {
    ServiceName string
    SourcePath  string
    TargetPath  string
    BackupPath  string
}

// Helper functions
func CopyFile(src, dst string) error {...} // lines 28-35
func GetServiceWorkers(eosRoot string) []ServiceWorkerInfo {...} // lines 38-79
func updateServiceWorker(rc *eos_io.RuntimeContext, worker ServiceWorkerInfo) error {...} // lines 148-208
func restartServiceIfRunning(ctx context.Context, serviceName string) error {...} // lines 211-234
func verifyOneshotCompletion(ctx context.Context, serviceName string) error {...} // lines 237-258
```

### Migration Target: `pkg/pipeline/services.go`

## Example 2: Services Management (cmd/update/services.go)

### Items to Migrate:
```go
// Package-level flag variables (lines 19-24)
var (
    servicesOutputJSON bool
    servicesDryRun     bool
    servicesShowAll    bool
    servicesSudo       bool
)

// Flag variables for list command (lines 54-61)
var (
    servicesListState      []string
    servicesListPattern    string
    servicesListEnabled    *bool
    servicesListRunning    *bool
    servicesListEnabledStr string
    servicesListRunningStr string
)

// Other flag variables
var servicesStartEnable bool      // line 151
var servicesStopDisable bool      // line 199
var servicesLogsFollow bool       // line 324
var servicesLogsLines int         // line 325
// ... (more log-related vars)

// Helper functions
func outputServiceList(result *system_services.ServiceListResult, outputJSON bool) error {...} // lines 385-411
func outputServiceOperation(result *system_services.ServiceOperation, outputJSON bool) error {...} // lines 413-439
func outputServiceStatus(result *system_services.ServiceInfo, outputJSON bool) error {...} // lines 441-473
```

### Migration Target: `pkg/system_services/output.go` and config structs

## Example 3: LDAP Certificate Management (cmd/update/ldap.go)

### Items to Migrate:
```go
// Variables (lines 14-16)
var (
    ipSAN  string
    dryRun bool
)

// The logic from RunE function should be extracted to:
func RegenerateLDAPCertificate(rc *eos_io.RuntimeContext, ipSAN string, dryRun bool) error {
    // Extract lines 24-52 into this function
}
```

### Migration Target: `pkg/ldap/certificate.go`

## Example 4: Pipeline Webhook Status (cmd/read/pipeline_webhook_status.go)

### Items to Migrate:
```go
// Type definition
type WebhookStatus struct {
    // Need to check the actual struct definition
}

// Helper functions
func checkWebhookStatus(rc *eos_io.RuntimeContext, verbose bool) *WebhookStatus {...}
func allFilesPresent(files map[string]bool) bool {...}
func checkEnvVar(envFile, varName string) bool {...}
func outputStatusJSON(status *WebhookStatus) error {...}
func outputStatusText(status *WebhookStatus, logger otelzap.LoggerWithCtx) error {...}
```

### Migration Target: `pkg/pipeline/webhook.go`

## Example 5: Ragequit Emergency Tool (cmd/ragequit/ragequit.go)

### Items to Migrate:
```go
// Variables (lines 149-154)
var (
    reason   string
    noReboot bool
    force    bool
    actions  string
)

// All helper functions like:
func confirmRagequit(rc *eos_io.RuntimeContext) bool {...}
func createTimestampFile(rc *eos_io.RuntimeContext, reason string) {...}
func detectEnvironment(rc *eos_io.RuntimeContext) {...}
func checkResources(rc *eos_io.RuntimeContext) {...}
func checkQueues(rc *eos_io.RuntimeContext) {...}
func checkDatabases(rc *eos_io.RuntimeContext) {...}
func securitySnapshot(rc *eos_io.RuntimeContext) {...}
func containerDiagnostics(rc *eos_io.RuntimeContext) {...}
func performanceSnapshot(rc *eos_io.RuntimeContext) {...}
func systemctlDiagnostics(rc *eos_io.RuntimeContext) {...}
func networkDiagnostics(rc *eos_io.RuntimeContext) {...}
func customHooks(rc *eos_io.RuntimeContext) {...}
func generateRecoveryPlan(rc *eos_io.RuntimeContext) {...}
func createPostRebootRecovery(rc *eos_io.RuntimeContext) {...}
func notifyRagequit(rc *eos_io.RuntimeContext) {...}
func flushDataSafety(rc *eos_io.RuntimeContext) {...}
func executeReboot(rc *eos_io.RuntimeContext) error {...}
func getHostname() string {...}
func getHomeDir() string {...}
```

### Migration Target: `pkg/emergency/` or `pkg/ragequit/`

## Example 6: Git Operations (cmd/self/git_commit.go)

### Items to Migrate:
```go
// Types
type GitStatus struct {...}
type ChangeAnalysis struct {...}

// Functions
func analyzeChanges(rc *eos_io.RuntimeContext, ...) (*ChangeAnalysis, error) {...}
func createCommit(rc *eos_io.RuntimeContext, ...) error {...}
// Other git-related helper functions
```

### Migration Target: `pkg/git_management/commit.go`

## Example 7: SSH Security (cmd/update/ssh.go)

### Items to Migrate:
```go
// Variables (lines 16-21)
var (
    sshHost      string
    sshKeyPath   string
    sshHosts     string
    sshUsername  string
)

// Logic from the command should be extracted to helper functions
```

### Migration Target: `pkg/ssh/secure.go`

## Example 8: Pipeline Prompts (cmd/update/pipeline_prompts.go)

### Items to Migrate:
```go
// Variables (lines 24-29)
var (
    promptsUpdateFromFile    string
    promptsUpdateInteractive bool
    promptsUpdateBackup      bool
    promptsUpdateAppendMode  bool
)

// Any helper functions for prompt management
```

### Migration Target: `pkg/pipeline/prompts.go`

## Pattern for Flag Variables Migration

### Current Pattern (BAD):
```go
// In cmd file
var flagValue string

func init() {
    cmd.Flags().StringVar(&flagValue, "flag", "", "description")
}

func runCommand(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Use flagValue directly
    doSomething(flagValue)
}
```

### New Pattern (GOOD):
```go
// In cmd file
func init() {
    cmd.Flags().String("flag", "", "description")
}

func runCommand(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    flagValue, _ := cmd.Flags().GetString("flag")
    
    // Call pkg function with flag as parameter
    return pkg.DoSomething(rc, flagValue)
}

// In pkg file
func DoSomething(rc *eos_io.RuntimeContext, flagValue string) error {
    // Implementation
}
```

## Constants Migration Examples

### Hecate Terraform Templates (cmd/create/hecate_terraform.go)
```go
const HecateTerraformTemplate = `...`
const HecateCloudInitTemplate = `...`
```
Target: `pkg/hecate/templates.go`

## Summary of Migration Rules

1. **Types**: Move all struct/interface definitions to `pkg/*/types.go`
2. **Functions**: Move all non-init functions to appropriate pkg files
3. **Constants**: Move all constants to pkg files
4. **Variables**: 
   - Flag variables: Use cmd.Flags().GetXXX() instead of package vars
   - Config variables: Move to config structs in pkg
   - Never use package-level mutable state in pkg

5. **Command Logic**: Extract RunE logic into pkg functions that:
   - Accept RuntimeContext as first parameter
   - Accept configuration as parameters or config structs
   - Return errors properly wrapped

6. **Output Functions**: Group by functionality in pkg:
   - JSON/text formatters go together
   - Use interfaces for different output formats