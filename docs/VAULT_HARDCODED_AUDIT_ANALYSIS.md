# Vault Hardcoded Values Audit Analysis

*Last Updated: 2025-10-21*

## Executive Summary

- **Total grep matches**: 494
- **False positives**: ~344 (70%)
- **Real violations**: ~150 (30%)
- **Critical violations**: 0 (all permissions already centralized)
- **High priority fixes needed**: ~60 path usage violations

## Violation Breakdown

### Category 1: FALSE POSITIVES (Keep As-Is)

#### 1.1 Constant Definitions (127 matches)
**Status**: These ARE the centralized constants - not violations

```go
// pkg/vault/constants.go
const (
    VaultTLSKeyPerm = 0600  // ← This is CORRECT, not a violation
    VaultConfigPerm = 0640  // ← This is CORRECT, not a violation
    // ... etc
)
```

**Action**: None - these are the solution, not the problem

#### 1.2 String Construction (48 URL matches)
**Status**: Acceptable - constructing URLs from variables

```go
// ACCEPTABLE
vaultAddr := fmt.Sprintf("https://%s:%d", hostname, port)  // Uses variables
clusterAddr := fmt.Sprintf("https://%s:%d", hostname, clusterPort)
```

**Action**: None - string construction is fine

#### 1.3 Command Literals (48 systemctl matches)
**Status**: Acceptable - command names must be literals

```go
// ACCEPTABLE
exec.Command("systemctl", "start", "vault")  // "systemctl" is the command name
exec.Command("journalctl", "-u", "vault")    // "journalctl" is the command name
```

**Action**: None - command names stay as literals

#### 1.4 Vault KV API Paths (45 secret/* matches)
**Status**: Acceptable - these are API paths, not filesystem paths

```go
// ACCEPTABLE - Vault API paths
client.Logical().Read("secret/data/eos/userpass-password")
pb.AddPath("secret/data/eos/{{identity.entity.name}}/*", "read")
```

**Action**: None - API paths can stay inline

### Category 2: REAL VIOLATIONS (Fix These)

#### 2.1 Hardcoded Paths in Code (60 matches) - HIGH PRIORITY

**Files**: cleanup/, uninstall.go, hardening.go, phase*.go

**Examples**:
```go
// WRONG - hardcoded paths
if err := os.Stat("/etc/vault.d/vault.hcl"); err != nil { ... }
if err := os.WriteFile("/etc/logrotate.d/vault", content, 0644); err != nil { ... }
if err := os.MkdirAll("/var/log/vault", 0750); err != nil { ... }

// CORRECT - use constants
if err := os.Stat(vault.VaultConfigPath); err != nil { ... }
if err := os.WriteFile("/etc/logrotate.d/vault", content, vault.VaultConfigPerm); err != nil { ... }
if err := os.MkdirAll(vault.VaultLogsDir, vault.VaultLogsDirPerm); err != nil { ... }
```

**Action**: Replace with vault.VaultConfigPath, vault.VaultLogsDir, etc.

#### 2.2 Hardcoded IPs/Hostnames (27 matches) - MEDIUM PRIORITY

**Files**: Various

**Examples**:
```go
// WRONG
ipAddresses["127.0.0.1"] = net.ParseIP("127.0.0.1")
DNSNames: []string{"localhost"}
if strings.Contains(content, "127.0.0.1") { ... }

// CORRECT
ipAddresses[vault.LocalhostIP] = net.ParseIP(vault.LocalhostIP)
DNSNames: []string{vault.LocalhostHostname}  // Need to add this constant
if strings.Contains(content, vault.LocalhostIP) { ... }
```

**Action**: Use vault.LocalhostIP, add vault.LocalhostHostname

#### 2.3 Hardcoded Ports in Strings (19 matches) - MEDIUM PRIORITY

**Files**: discovery.go, config_validator.go, config_fix.go

**Examples**:
```go
// WRONG
if strings.Contains(content, ":8200") { ... }
fmt.Sprintf("https://127.0.0.1:8200")

// CORRECT
if strings.Contains(content, fmt.Sprintf(":%d", shared.PortVault)) { ... }
fmt.Sprintf("https://%s:%d", vault.LocalhostIP, shared.PortVault)
```

**Action**: Use shared.PortVault, shared.PortVaultEos

#### 2.4 Hardcoded Service/User/Group Names (24 matches) - MEDIUM PRIORITY

**Files**: Various

**Examples**:
```go
// WRONG
exec.Command("systemctl", "start", "vault.service")
Owner: "vault"
Group: "vault"

// CORRECT
exec.Command("systemctl", "start", vault.VaultServiceName)
Owner: vault.VaultOwner
Group: vault.VaultGroup
```

**Action**: Use vault.VaultServiceName, vault.VaultOwner, vault.VaultGroup

#### 2.5 Hardcoded Timeouts (19 matches) - LOW PRIORITY

**Files**: Various

**Examples**:
```go
// WRONG
Timeout: 10 * time.Second
time.Sleep(2 * time.Second)

// CORRECT
Timeout: vault.VaultHealthTimeout  // If appropriate
time.Sleep(vault.VaultRetryDelay)
```

**Action**: Centralize common timeouts, allow one-off timeouts to stay inline

#### 2.6 Hardcoded Environment Variable Names (14 matches) - LOW PRIORITY

**Files**: Various

**Examples**:
```go
// WRONG
os.Getenv("VAULT_ADDR")
os.Setenv("VAULT_TOKEN", token)

// CORRECT (ALREADY EXISTS)
os.Getenv(vault.EnvVaultAddress)
os.Setenv(vault.EnvVaultToken, token)
```

**Action**: Use vault.EnvVaultAddress, vault.EnvVaultToken (already in constants.go)

## Priority Action Plan

### Phase 1: HIGH PRIORITY (60 violations) - CRITICAL PATH
- [ ] Replace hardcoded paths in pkg/vault/cleanup/*.go
- [ ] Replace hardcoded paths in pkg/vault/uninstall.go
- [ ] Replace hardcoded paths in pkg/vault/hardening.go
- [ ] Replace hardcoded paths in pkg/vault/phase*.go

### Phase 2: MEDIUM PRIORITY (70 violations) - FUNCTIONAL
- [ ] Replace hardcoded IPs (127.0.0.1 → vault.LocalhostIP)
- [ ] Add vault.LocalhostHostname constant for "localhost"
- [ ] Replace hardcoded ports in string checks
- [ ] Replace hardcoded service/user/group names

### Phase 3: LOW PRIORITY (20 violations) - POLISH
- [ ] Replace hardcoded environment variable names
- [ ] Centralize common timeouts (keep one-offs inline)

## Constants to Add to vault/constants.go

```go
// === Hostname Constants ===
const (
    LocalhostHostname = "localhost"  // NEW: Localhost hostname
    VaultHostname     = "vault"      // NEW: Default Vault hostname
)

// === System Paths (non-Vault) ===
const (
    // Logrotate
    LogrotateConfigDir = "/etc/logrotate.d"           // NEW
    LogrotateVaultPath = "/etc/logrotate.d/vault"    // NEW

    // Security limits
    SecurityLimitsDir         = "/etc/security/limits.d"                    // NEW
    VaultHardeningConfigPath  = "/etc/security/limits.d/vault-hardening.conf"  // NEW
    VaultUlimitsConfigPath    = "/etc/security/limits.d/vault-ulimits.conf"    // NEW

    // Tmpfiles
    TmpfilesConfigDir  = "/etc/tmpfiles.d"      // NEW
    EosTmpfilesPath    = "/etc/tmpfiles.d/eos.conf"  // NEW

    // System CA certificates
    SystemCACertDir    = "/usr/local/share/ca-certificates"                   // NEW
    VaultSystemCACert  = "/usr/local/share/ca-certificates/vault-local-ca.crt"  // NEW
)

// === Command Timeouts (commonly used) ===
const (
    ServiceStartTimeout = 10 * time.Second  // NEW: systemctl start timeout
    ServiceStopTimeout  = 30 * time.Second  // NEW: systemctl stop timeout
    HTTPClientTimeout   = 30 * time.Second  // NEW: HTTP client default timeout
)
```

## Files Requiring Updates (Detailed)

### cleanup/ package (14 files)
- `cleanup/files.go`: 3 paths → use VaultProfilePath, TmpVaultGlob
- `cleanup/hardening.go`: 8 paths → use new constants above
- `cleanup/packages.go`: 3 paths → use new constants
- `cleanup/services.go`: 1 name → use VaultServiceName
- `cleanup/verify.go`: 5 paths → use existing constants

### uninstall.go (30+ violations)
- Lines 90-92: logDir → use shared or vault constant
- Lines 290-293: service paths → use VaultServicePath, VaultAgentServicePath
- Lines 437-448: env files, env vars → use new constants
- Lines 539-544: path descriptions → use existing constants
- Lines 964-1019: Consul storage paths → acceptable (API paths)

### hardening.go (20+ violations)
- Lines 269-285: fstab operations → acceptable (OS config)
- Lines 306-318: systemd overrides → use new constants
- Lines 330-351: security limits → use new SecurityLimits* constants
- Lines 404-469: SSH config → acceptable (OS config)
- Lines 580-580: logrotate → use LogrotateVaultPath
- Lines 640-704: backup scripts → use new constants

### phase*.go files (20+ violations)
- `phase2_env_setup.go`: 3 CA paths → use new constants
- `phase3_tls_cert.go`: 2 CA paths → use SystemCACertDir, VaultSystemCACert
- `phase4_config.go`: 2 config operations → already correct
- `phase13_write_agent_config.go`: 3 paths → use EosTmpfilesPath, EosRunDir
- `phase14_start_agent_and_validate.go`: 4 paths → use EosRunDir

## Grep False Positive Analysis

| Category | Total Matches | False Positives | Real Violations | Notes |
|----------|---------------|-----------------|-----------------|-------|
| File Permissions | 127 | 127 (100%) | 0 | All are constant definitions |
| File Paths | 118 | 30 (25%) | 88 (75%) | Mix of constants and usage |
| IP Addresses | 27 | 0 | 27 (100%) | All need fixing |
| Port Numbers | 19 | 0 | 19 (100%) | All need fixing |
| Service Names | 24 | 0 | 24 (100%) | All need fixing |
| Env Vars | 14 | 0 | 14 (100%) | All need fixing |
| URLs | 48 | 48 (100%) | 0 | String construction OK |
| Timeouts | 19 | 10 (53%) | 9 (47%) | Some acceptable |
| Commands | 48 | 48 (100%) | 0 | Command literals OK |
| Storage Paths | 45 | 45 (100%) | 0 | API paths OK |
| Config Files | 4 | 1 (25%) | 3 (75%) | Some already constants |
| **TOTAL** | **494** | **309 (63%)** | **185 (37%)** | Actual work: ~185 fixes |

## Conclusion

The audit found 494 grep matches, but **63% are false positives**:
- Constant definitions themselves (127)
- Acceptable string construction (48)
- Acceptable command literals (48)
- Acceptable API paths (45)
- Other acceptable patterns (41)

**Real work**: ~185 violations across 4 priority categories.

**Next steps**:
1. Add missing constants to vault/constants.go
2. Phase 1: Fix HIGH priority path violations (60 fixes)
3. Phase 2: Fix MEDIUM priority network/service violations (70 fixes)
4. Phase 3: Fix LOW priority environment/timeout violations (20 fixes)
5. Re-run audit to verify 0 violations
6. Move to Consul package
