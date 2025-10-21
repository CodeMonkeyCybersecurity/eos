# Vault Path Centralization - Phase 1 Complete

*Last Updated: 2025-10-21*

## Executive Summary

Successfully centralized all Vault-related constants into **pkg/vault/constants.go** and created structured types in **pkg/vault/types.go**. This eliminates the critical binary path conflict and provides a foundation for systematic replacement of all 200+ hardcoded paths across 26 files.

## Critical Issue Resolved

**Binary Path Conflict** (P0 - Breaking):
- ✅ **FIXED**: Conflicting definitions eliminated
  - `pkg/shared/vault_server.go`: Now deprecated, references `/usr/local/bin/vault`
  - `pkg/vault/constants.go`: **SINGLE SOURCE OF TRUTH** = `/usr/local/bin/vault`
- ✅ **VERIFIED**: All pkg/vault references updated to use `vault.VaultBinaryPath`
- ✅ **TESTED**: `go vet ./pkg/vault/...` passes

## Phase 1 Deliverables

### 1. Centralized Constants (pkg/vault/constants.go)

```go
// Binary Locations
VaultBinaryPath           = VaultBinaryPath      // PRIMARY
VaultBinaryPathLegacy     = VaultBinaryPath            // Legacy (cleanup)
VaultBinaryPathOpt        = "/opt/vault/bin/vault"      // Alternative
VaultBinaryPathSnap       = "/snap/bin/vault"           // Snap package

// Configuration Paths
VaultConfigDir            = "/etc/vault.d"
VaultConfigPath           = "/etc/vault.d/vault.hcl"
VaultAgentConfigFile      = "vault-agent.hcl"

// TLS Certificates
VaultTLSDir               = "/etc/vault.d/tls"
VaultTLSCert              = "/etc/vault.d/tls/vault.crt"
VaultTLSKey               = "/etc/vault.d/tls/vault.key"
VaultTLSCA                = "/etc/vault.d/tls/ca.crt"

// Data and Logs
VaultDataDir              = "/opt/vault/data"
VaultLogsDir              = "/var/log/vault"
VaultAuditLogPath         = "/var/log/vault/vault-audit.log"

// Systemd Services
VaultServicePath          = "/etc/systemd/system/vault.service"
VaultAgentServicePath     = "/etc/systemd/system/vault-agent-eos.service"

// Helper Scripts
VaultBackupScriptPath     = "/usr/local/bin/vault-backup.sh"
VaultAgentHealthCheckPath = "/usr/local/bin/vault-agent-health-check.sh"
VaultSnapshotScriptPath   = "/usr/local/bin/vault-snapshot.sh"

// Network Configuration
VaultListenAddr           = "0.0.0.0"                    // Bind address
VaultClientAddr           = "127.0.0.1"                  // Client connection
VaultDefaultPort          = 8179                         // API port (Eos custom)
VaultClusterPort          = 8180                         // Raft cluster port

// File Permissions
VaultDirPerm              = 0755                         // rwxr-xr-x
VaultTLSKeyPerm           = 0600                         // rw-------
VaultConfigPerm           = 0644                         // rw-r--r--
```

### 2. Structured Types (pkg/vault/types.go)

Added **four new types** for structured path management:

#### VaultPaths
```go
type VaultPaths struct {
    Binary       string      // Primary vault binary
    BinaryLegacy []string    // Legacy locations for cleanup
    ConfigDir    string      // Base config directory
    ConfigFile   string      // Main server config
    TLSDir       string      // TLS certificate directory
    TLSCert      string      // Server certificate
    TLSKey       string      // Server private key
    // ... 14 total fields
}

// Constructor
func DefaultVaultPaths() *VaultPaths

// Utilities
func (vp *VaultPaths) AllPaths() []string  // Flat list for cleanup
```

#### VaultNetworkConfig
```go
type VaultNetworkConfig struct {
    ListenAddr        string  // 0.0.0.0 (bind all interfaces)
    ClusterListenAddr string  // 0.0.0.0
    ClientAddr        string  // 127.0.0.1 or hostname
    APIPort           int     // 8179
    ClusterPort       int     // 8180
    APIAddress        string  // Computed: https://hostname:8179
    ClusterAddress    string  // Computed: https://hostname:8180
}

// Constructor
func DefaultVaultNetwork(hostname string) *VaultNetworkConfig

// Utilities
func (vnc *VaultNetworkConfig) APIListenAddress() string      // "0.0.0.0:8179"
func (vnc *VaultNetworkConfig) ClusterListenAddress() string  // "0.0.0.0:8180"
func (vnc *VaultNetworkConfig) LocalAPIAddress() string       // "https://127.0.0.1:8179"
```

#### VaultServiceConfig
```go
type VaultServiceConfig struct {
    ServiceName string  // "vault.service"
    User        string  // "vault"
    Group       string  // "vault"
    BinaryPath  string  // VaultBinaryPath
    ConfigPath  string  // "/etc/vault.d/vault.hcl"
}

// Constructor
func DefaultVaultService() *VaultServiceConfig

// Utilities
func (vsc *VaultServiceConfig) ExecStartCommand() string  // Full systemd ExecStart line
```

#### VaultInstallConfig
```go
type VaultInstallConfig struct {
    Paths     *VaultPaths
    Network   *VaultNetworkConfig
    Service   *VaultServiceConfig
    LogLevel  string
    LogFormat string
}

// Constructor
func DefaultInstallConfig(hostname string) *VaultInstallConfig
```

### 3. Files Successfully Updated

✅ **pkg/vault/constants.go** - Centralized all constants
✅ **pkg/vault/types.go** - Added structured configuration types
✅ **pkg/vault/phase_delete.go** - Uses `VaultBinaryPath`
✅ **pkg/vault/binary_cleanup.go** - Uses `VaultBinaryPath`, removed unused import
✅ **pkg/vault/fix/fix.go** - Uses `vault.VaultBinaryPath`
✅ **pkg/vault/phase5_start_service.go** - Uses `DefaultVaultService()` for systemd unit
✅ **cmd/repair/vault.go** - Uses `vault.VaultBinaryPath`
✅ **pkg/shared/vault_server.go** - Deprecated conflicting constants, backward compatible

### 4. Automated Discovery Tool

Created **scripts/find_hardcoded_vault_paths.sh** that:
- Scans entire codebase for hardcoded paths
- Categorizes by type (binary, config, TLS, data, scripts, network)
- Generates actionable report at `/tmp/vault_hardcoded_paths.txt`
- Lists all files requiring updates (26 files)
- Provides replacement constant reference

Usage:
```bash
./scripts/find_hardcoded_vault_paths.sh
cat /tmp/vault_hardcoded_paths.txt
```

## Remaining Work (Phase 2)

### Files Requiring Updates: 26

**Priority 1 - Core Functionality (8 files)**:
1. **pkg/vault/install.go** - Installation paths
2. **pkg/vault/uninstall.go** - Cleanup paths
3. **pkg/vault/config_builder.go** - Configuration generation
4. **pkg/vault/cert_renewal.go** - TLS certificate paths
5. **pkg/vault/agent_lifecycle.go** - Agent scripts and health checks
6. **pkg/vault/hardening.go** - Backup scripts and systemd paths
7. **pkg/vault/consul_integration_check.go** - Config path
8. **pkg/vault/consul_registration.go** - Network addresses

**Priority 2 - Support & Debug (10 files)**:
9. **pkg/debug/vault/diagnostics.go** - Hardcoded paths for debugging
10. **pkg/debug/vault/tls.go** - TLS path checks
11. **pkg/servicestatus/vault.go** - Status checking
12. **pkg/servicestatus/consul.go** - Cross-service checks
13. **pkg/sync/connectors/consul_vault.go** - Sync operations (5 instances)
14. **pkg/environment/server_detection.go** - Environment discovery
15. **pkg/inspect/services.go** - Service inspection
16. **pkg/ubuntu/apparmor.go** - AppArmor profiles
17. **pkg/nuke/assess.go** - System cleanup
18. **pkg/consul/remove.go** - Consul removal paths

**Priority 3 - Non-Vault Packages (2 files)**:
19. **cmd/debug/bootstrap.go** - Bootstrap diagnostics
20. **cmd/read/verify.go** - Verification commands

**Test Files (6 files)**:
21. pkg/vault/binary_cleanup_test.go
22. pkg/vault/config_validator_test.go
23. pkg/vault/historical_issues_regression_test.go
24. pkg/vault/config_parser_test.go
25. pkg/vault/cleanup/verify.go
26. pkg/nuke/assess_test.go

### Replacement Strategy

**Option 1: Manual (Surgical)**
- Update each file individually
- Maintain full control
- Verify each change compiles
- Estimated: 3-4 hours

**Option 2: Automated (Batch)**
Create a sed/awk script:
```bash
# Example for binary path
find pkg/vault -name "*.go" -type f -exec sed -i '' \
    's|VaultBinaryPath|VaultBinaryPath|g' {} +

# Example for config paths
find pkg/vault -name "*.go" -type f -exec sed -i '' \
    's|"/etc/vault\.d/vault\.hcl"|VaultConfigPath|g' {} +
```

**Recommended: Hybrid**
1. Automated batch replacement for simple patterns
2. Manual review of diffs
3. Fix compilation errors
4. Run full test suite

### Verification Checklist

Before considering Phase 2 complete:

- [ ] All 26 files updated with constants
- [ ] All test files updated
- [ ] `go build -o /tmp/eos-build ./cmd/` succeeds
- [ ] `go vet ./pkg/...` passes
- [ ] `go vet ./cmd/...` passes
- [ ] `go test -v ./pkg/vault/...` passes
- [ ] No grep results for hardcoded `/usr/local/bin/vault` (except constants.go)
- [ ] No grep results for hardcoded `/etc/vault.d/` (except constants.go)
- [ ] Documentation updated

## Impact & Benefits

### Immediate Benefits (Phase 1)

1. ✅ **Critical Bug Fixed**: Binary path conflict resolved
2. ✅ **Single Source of Truth**: All constants in one file
3. ✅ **Type Safety**: Structured configuration prevents errors
4. ✅ **Self-Documenting**: Constants include clear comments
5. ✅ **Testable**: Can mock configurations easily
6. ✅ **Discoverable**: Automated tool finds all hardcoded paths

### Future Benefits (Post Phase 2)

1. **Maintainability**: Change paths once, apply everywhere
2. **Testing**: Easy to swap paths for integration tests
3. **Flexibility**: Support different deployment scenarios
4. **Documentation**: VaultFilePermissions table for validation
5. **Security**: Standardized secure permissions
6. **Portability**: Easier to support non-standard installations

## Migration Guide

### For New Code

**DO** use constants:
```go
import "github.com/CodeMonkeyCybersecurity/eos/pkg/vault"

// Use constants
binaryPath := vault.VaultBinaryPath
configPath := vault.VaultConfigPath
tlsCert := vault.VaultTLSCert

// Or use structured types
paths := vault.DefaultVaultPaths()
network := vault.DefaultVaultNetwork("athena.example.com")
service := vault.DefaultVaultService()
```

**DON'T** hardcode:
```go
// ✗ WRONG
binaryPath := VaultBinaryPath
configPath := "/etc/vault.d/vault.hcl"
listenAddr := "0.0.0.0:8179"
```

### For Existing Code

1. Import `"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"`
2. Replace hardcoded strings with constants
3. For network addresses, use `VaultNetworkConfig`
4. For systemd, use `VaultServiceConfig.ExecStartCommand()`

## Tools & Scripts

### Discovery Tool
```bash
# Find all hardcoded paths
./scripts/find_hardcoded_vault_paths.sh

# Review report
cat /tmp/vault_hardcoded_paths.txt
```

### Validation
```bash
# Verify no hardcoded binary paths (except constants.go)
grep -r 'VaultBinaryPath' pkg/vault --include="*.go" | grep -v constants.go

# Verify no hardcoded config paths (except constants.go)
grep -r '"/etc/vault.d"' pkg/vault --include="*.go" | grep -v constants.go

# Check compilation
go build -o /tmp/eos-build ./cmd/

# Run tests
go test -v ./pkg/vault/...
```

## Timeline

- **Phase 1** (Completed): Centralize constants, create types, fix critical conflict
- **Phase 2** (Planned): Replace all 200+ hardcoded paths in 26 files
- **Phase 3** (Future): Add validation tooling, permissions enforcement

## References

- [pkg/vault/constants.go](../pkg/vault/constants.go) - **SINGLE SOURCE OF TRUTH**
- [pkg/vault/types.go](../pkg/vault/types.go) - Structured configuration types
- [scripts/find_hardcoded_vault_paths.sh](../scripts/find_hardcoded_vault_paths.sh) - Discovery tool
- [VAULT_CONSTANTS_CENTRALIZATION.md](./VAULT_CONSTANTS_CENTRALIZATION.md) - Detailed analysis
- [/tmp/vault_hardcoded_paths.txt]() - Latest scan results

---

**Status**: Phase 1 Complete ✅ | Phase 2 Ready to Begin
