# Vault Constants Centralization

*Last Updated: 2025-10-21*

## Summary

This document describes the centralization of all Vault-related constants into a single source of truth at [pkg/vault/constants.go](../pkg/vault/constants.go).

## Problem Statement

Prior to this refactoring, Vault-related constants were scattered across multiple files with **conflicting definitions**:

### Binary Path Conflict (Critical)

- **pkg/shared/vault_server.go:37**: `VaultBinaryPath = VaultBinaryPath`
- **pkg/vault/constants.go:74**: `VaultBinaryPath = "VaultBinaryPath"`
- **pkg/vault/install.go:148**: Hardcoded `VaultBinaryPath`

**Impact**: Deletion code removed `/usr/bin/vault` but left `VaultBinaryPath` behind, causing incomplete uninstallation.

### Configuration Path Duplication

Multiple files defined:
- `/etc/vault.d/vault.hcl`
- `/etc/vault.d/tls/`
- TLS certificate paths
- Data directory paths
- Systemd service paths

### Network Address Confusion

Mixed usage of:
- `shared.GetInternalHostname` (localhost loopback)
- `0.0.0.0` (bind all interfaces)
- `localhost` (hostname)
- Hardcoded port numbers

## Solution: Single Source of Truth

All Vault constants are now defined in **[pkg/vault/constants.go](../pkg/vault/constants.go)**.

### Binary Locations

```go
const (
    VaultBinaryPath = "VaultBinaryPath" // PRIMARY location
)
```

**Decision**: `VaultBinaryPath` is the canonical location (matches install.go behavior).

### Configuration Directories

```go
const (
    VaultConfigDir     = "/etc/vault.d"                   // Base config directory
    VaultConfigPath    = "/etc/vault.d/vault.hcl"         // Main server config
    VaultTLSDir        = "/etc/vault.d/tls"               // TLS certificate directory
    VaultTLSCert       = "/etc/vault.d/tls/vault.crt"     // TLS certificate
    VaultTLSKey        = "/etc/vault.d/tls/vault.key"     // TLS private key
)
```

### Data and Log Directories

```go
const (
    VaultDataDir      = "/opt/vault/data"                // Data storage
    VaultLogsDir      = "/var/log/vault"                 // Log directory
    VaultAuditLogPath = "/var/log/vault/vault-audit.log" // Audit log file
)
```

### Systemd Services

```go
const (
    VaultServiceName      = "vault.service"               // Systemd service name
    VaultAgentServiceName = "vault-agent-eos.service"     // Agent service name
    VaultServicePath      = "/etc/systemd/system/vault.service"
    VaultAgentServicePath = "/etc/systemd/system/vault-agent-eos.service"
)
```

### Network Endpoints

```go
const (
    VaultListenAddr   = "0.0.0.0"     // Bind address (all interfaces)
    VaultClientAddr   = "shared.GetInternalHostname"   // Client connection address (localhost)
    VaultDefaultPort  = 8179          // CUSTOM: Vault API port
    VaultClusterPort  = 8180          // Raft cluster port
)
```

**Rationale**:
- Vault **listens** on `0.0.0.0` (all interfaces) for flexibility
- Clients **connect** to `shared.GetInternalHostname` or hostname for security
- Port `8179` is Eos custom (not HashiCorp default 8200)

### File Permissions and Ownership

**NEW**: Standardized permissions for all Vault files:

```go
const (
    // Directory Permissions
    VaultDirPerm        = 0755 // rwxr-xr-x - Directories (vault:vault)
    VaultTLSDirPerm     = 0755 // rwxr-xr-x - TLS directory (vault:vault)
    VaultDataDirPerm    = 0700 // rwx------ - Data directory (vault:vault)
    VaultSecretsDirPerm = 0700 // rwx------ - Secrets directory (vault:vault)

    // File Permissions
    VaultConfigPerm      = 0644 // rw-r--r-- - Config files (vault:vault)
    VaultTLSCertPerm     = 0644 // rw-r--r-- - Public certificates (vault:vault)
    VaultTLSKeyPerm      = 0600 // rw------- - Private keys (vault:vault)
    VaultSecretFilePerm  = 0600 // rw------- - Secret files (vault:vault)
    VaultBinaryPerm      = 0755 // rwxr-xr-x - Binary executable (root:root)
    VaultLogPerm         = 0640 // rw-r----- - Log files (vault:vault)

    // Owner/Group
    VaultOwner = "vault"
    VaultGroup = "vault"
    RootOwner  = "root"
    RootGroup  = "root"
)
```

### VaultFilePermissions Table

A centralized table defines expected ownership and permissions for all Vault files:

```go
var VaultFilePermissions = []FilePermission{
    // Directories
    {Path: VaultConfigDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultDirPerm},
    {Path: VaultTLSDir, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSDirPerm},

    // Config files
    {Path: VaultConfigPath, Owner: VaultOwner, Group: VaultGroup, Mode: VaultConfigPerm},

    // TLS files
    {Path: VaultTLSCert, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSCertPerm},
    {Path: VaultTLSKey, Owner: VaultOwner, Group: VaultGroup, Mode: VaultTLSKeyPerm},

    // Binary
    {Path: VaultBinaryPath, Owner: RootOwner, Group: RootGroup, Mode: VaultBinaryPerm},
}
```

**Use case**: Validation and enforcement of correct permissions after installation or upgrades.

## Migration Path

### Deprecated Constants in pkg/shared/vault_server.go

For backward compatibility, deprecated constants remain with clear documentation:

```go
// DEPRECATED: Use vault.VaultBinaryPath instead
const VaultBinaryPath = "VaultBinaryPath"

// DEPRECATED: Use vault.VaultServiceName instead
const VaultServiceName = "vault.service"

// DEPRECATED: Use vault.VaultConfigDir instead
const VaultConfigDirDebian = "/etc/vault.d"
```

These will be removed in a future major version after all external references are updated.

### Files Updated

1. **pkg/vault/constants.go** - Single source of truth (expanded)
2. **pkg/shared/vault_server.go** - Deprecated duplicates, added compatibility shims
3. **pkg/vault/phase_delete.go** - Updated to use `vault.VaultBinaryPath`
4. **pkg/vault/binary_cleanup.go** - Updated to use `vault.VaultBinaryPath`
5. **pkg/vault/fix/fix.go** - Updated to use `vault.VaultBinaryPath`
6. **cmd/repair/vault.go** - Updated to use `vault.VaultBinaryPath`

## Verification

Run these commands to verify correct usage:

```bash
# Check for any remaining hardcoded paths
grep -r VaultBinaryPath --include="*.go" pkg/
grep -r "VaultBinaryPath" --include="*.go" pkg/ | grep -v constants.go

# Verify no compilation errors
go vet ./pkg/vault/...
go vet ./cmd/repair/...

# Build check (ignoring unrelated ceph library issue)
go build -o /tmp/eos-build ./cmd/
```

## Benefits

1. **Single Source of Truth**: All paths defined once in pkg/vault/constants.go
2. **Type Safety**: Go compiler enforces correct usage
3. **Self-Documenting**: Constants include comments explaining purpose
4. **Validation Ready**: VaultFilePermissions table enables automated checks
5. **Network Clarity**: Explicit distinction between listen and client addresses
6. **Security**: Standardized secure permissions for sensitive files

## Future Work

- [ ] Migrate all `shared.VaultConfigDirDebian` references to `vault.VaultConfigDir`
- [ ] Migrate all `shared.VaultServiceName` references to `vault.VaultServiceName`
- [ ] Add validation function to check VaultFilePermissions on live system
- [ ] Add `eos read vault permissions` command to display current state
- [ ] Add `eos repair vault permissions` to fix incorrect permissions

## References

- [pkg/vault/constants.go](../pkg/vault/constants.go) - Centralized constants
- [pkg/shared/vault_server.go](../pkg/shared/vault_server.go) - Deprecated constants with compatibility shims
- [CLAUDE.md](../CLAUDE.md) - Project conventions
