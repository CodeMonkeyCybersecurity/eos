# Command Refactoring Plan: Subcommands → Flags

*Last Updated: 2025-10-20*

## Overview

Refactor Eos command structure to improve UX by converting related subcommands into flags under a single parent command.

**Goal**: Better discoverability, cleaner help text, logical grouping.

## Design Pattern

### Before (Anti-pattern)
```bash
eos read wazuh           # base command
eos read wazuh-ccs       # separate command
eos read wazuh-version   # separate command
eos read wazuh-agents    # separate command
```

**Problems**:
- Poor discoverability (`eos read wazuh --help` doesn't show related commands)
- Namespace pollution (too many top-level commands)
- Inconsistent mental model

### After (Preferred)
```bash
eos read wazuh              # default: show main data
eos read wazuh --ccs        # flag: show CCS platform
eos read wazuh --version    # flag: show version
eos read wazuh --agents     # flag: show agents
```

**Benefits**:
- `eos read wazuh --help` shows ALL wazuh options
- Cleaner command list
- Flags group related functionality

---

## Refactoring Groups

### Group 1: Wazuh Commands (HIGH PRIORITY - Reference Implementation)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `wazuh` | `wazuh` | (default) | Read Wazuh data |
| `wazuh-ccs` | `wazuh` | `--ccs` | Read Wazuh MSSP platform status |
| `wazuh-version` | `wazuh` | `--version` | Show Wazuh version information |
| `wazuh-agents` | `wazuh` | `--agents` | Show Wazuh agents |

**Files to modify**:
- `cmd/read/wazuh.go` (parent command)
- `cmd/read/wazuh_ccs.go` → merge into wazuh.go
- `cmd/read/wazuh_version.go` → merge into wazuh.go (if exists)
- `cmd/read/wazuh_agents.go` → merge into wazuh.go

**Implementation**:
```go
var readWazuhCmd = &cobra.Command{
    Use:   "wazuh",
    Short: "Read Wazuh (Wazuh) data",
    Long: `Read Wazuh data and status.

Available options:
  (default)    Show main Wazuh data
  --ccs        Show MSSP platform status
  --version    Show version information
  --agents     Show agent information`,
    RunE: eos.Wrap(runReadWazuh),
}

func init() {
    readWazuhCmd.Flags().Bool("ccs", false, "Show Wazuh MSSP platform status")
    readWazuhCmd.Flags().Bool("version", false, "Show Wazuh version information")
    readWazuhCmd.Flags().Bool("agents", false, "Show Wazuh agents")
}

func runReadWazuh(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    ccs, _ := cmd.Flags().GetBool("ccs")
    version, _ := cmd.Flags().GetBool("version")
    agents, _ := cmd.Flags().GetBool("agents")

    if ccs {
        return runReadWazuhCCS(rc, cmd, args)
    }
    if version {
        return runReadWazuhVersion(rc, cmd, args)
    }
    if agents {
        return runReadWazuhAgents(rc, cmd, args)
    }

    // Default behavior
    return runReadWazuhDefault(rc, cmd, args)
}
```

---

### Group 2: Vault Commands (HIGH PRIORITY - Reference Implementation)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `vault` | `vault` | (default) | Inspect current Vault paths |
| `vault-init` | `vault` | `--init` | Securely inspect Vault initialization data |
| `vault-status` | `vault` | `--status` | Show comprehensive Vault status |

**Files to modify**:
- `cmd/read/vault.go` (parent - need to check if exists)
- `cmd/read/vault_init.go` → merge
- `cmd/read/vault_status.go` → merge

---

### Group 3: Database Commands (HIGH PRIORITY - Reference Implementation)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `database-credentials` | `database` | `--credentials` | Generate and view dynamic database credentials |
| `database-status` | `database` | `--status` | Get database status information |

**Files to modify**:
- Create `cmd/read/database.go` (new parent)
- `cmd/read/database_credentials.go` → merge
- `cmd/read/database_status.go` → merge

---

### Group 4: Storage Commands (MEDIUM PRIORITY)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `storage` | `storage` | (default) | Retrieve storage device info |
| `storage-analyze` | `storage` | `--analyze` | Analyze storage state |
| `storage-monitor` | `storage` | `--monitor` | Monitor storage thresholds |
| `storage-metrics` | `storage` | `--metrics` | Show storage metrics |
| `storage-status` | `storage` | `--status` | Show storage status |

**Files to modify**:
- `cmd/read/storage.go` (parent)
- `cmd/read/storage_analyze.go` → merge
- `cmd/read/storage_monitor.go` → merge
- Others → merge

---

### Group 5: Hecate Commands (MEDIUM PRIORITY)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `hecate` | `hecate` | (default) | Inspect Hecate-managed services |
| `hecate-backend` | `hecate` | `--backend [id]` | Read backend connection details |
| `hecate-route` | `hecate` | `--route` | Read route details |
| `hecate-health` | `hecate` | `--health` | Read health status |
| `hecate-metrics` | `hecate` | `--metrics` | Read metrics |
| `hecate-dns` | `hecate` | `--dns` | Read DNS configuration |

**Files to modify**:
- `cmd/read/hecate.go` (parent)
- `cmd/read/hecate_backend.go` → merge
- `cmd/read/hecate_route.go` → merge
- `cmd/read/hecate_health.go` → merge
- Others → merge

---

### Group 6: Container Commands (MEDIUM PRIORITY)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `container-compose` | `container` | `--compose` | Find and inspect Docker Compose projects |

**Files to modify**:
- Create `cmd/read/container.go` (new parent)
- `cmd/read/container_compose.go` → merge

---

### Group 7: Crypto Commands (MEDIUM PRIORITY)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `crypto-info` | `crypto` | `--info` | Display cryptographic implementation info |

**Files to modify**:
- Create `cmd/read/crypto.go` (new parent)
- `cmd/read/crypto_info.go` → merge

---

### Group 8: ML-KEM Commands (MEDIUM PRIORITY)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `mlkem-secret` | `mlkem` | `--secret <key> <ct>` | Decapsulate shared secret |
| `mlkem-validation` | `mlkem` | `--validation <type> <key>` | Validate ML-KEM keys |

**Files to modify**:
- Create `cmd/read/mlkem.go` (new parent)
- `cmd/read/mlkem_secret.go` → merge
- `cmd/read/mlkem_validation.go` → merge

---

### Group 9: Remote Commands (MEDIUM PRIORITY)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `remote-debug` | `remote` | `--debug [host]` | Diagnose and fix remote issues |

**Files to modify**:
- Create `cmd/read/remote.go` (new parent)
- `cmd/read/remote_debug.go` → merge

---

### Group 10: System Commands (LOW PRIORITY - Already Good)

| Current Command | New Structure | Flag | Description |
|----------------|---------------|------|-------------|
| `system` | `system` | (default) | Collect system information |
| `system-path` | `system` | `--path` | Diagnose PATH configuration |

**Files to modify**:
- `cmd/read/system.go` (parent)
- `cmd/read/system_path.go` → merge

---

## Commands to Keep As-Is (No Refactoring Needed)

These are standalone commands with no related variants:

- `check` - Check eos installation
- `config` - Read Consul KV config value
- `consul` - Read Consul status
- `discovery` - Discover internal network assets
- `disk` - Inspect disk health
- `disk-usage` - Show disk usage
- `environment` - Display environment configuration
- `infra` - Inspect infrastructure components
- `inspect` - Inspect infrastructure/services
- `kvm` - List KVM VMs
- `ldap` - Auto-discover LDAP
- `logs` - Inspect Eos logs
- `nomad` - Read Nomad status
- `ollama` - Inspect Ollama setup
- `process` - Retrieve process information
- `secrets` - Inspect secrets in Pandora
- `show` - Show environment details
- `smartctl` - Check SMART health
- `status` - Check eos-managed infrastructure status
- `tailscale` - Display Tailscale network status
- `users` - Retrieve user information
- `verify` - Verify infrastructure state

---

## Implementation Strategy

### Phase 1: Reference Implementation (HIGH PRIORITY)
1. **Wazuh** - Most complex, good test case
2. **Vault** - Medium complexity
3. **Database** - Simple, clean example

### Phase 2: Medium Priority Groups
4. Storage
5. Hecate
6. Container
7. Crypto
8. ML-KEM
9. Remote

### Phase 3: Low Priority
10. System

---

## Testing Checklist

For each refactored command:
- [ ] `eos read <cmd> --help` shows all options
- [ ] Default behavior (no flags) works
- [ ] Each flag works independently
- [ ] Mutually exclusive flags handled gracefully
- [ ] Error messages are clear
- [ ] Backward compatibility considered (aliases if needed)

---

## Migration Notes

**Breaking Changes**: Users with scripts using old command names need to update.

**Mitigation**:
- Add aliases for backward compatibility where critical
- Document migration in changelog
- Provide migration guide

**Example**:
```go
// Backward compatibility alias
ReadCmd.AddCommand(&cobra.Command{
    Use:   "wazuh-ccs",
    Short: "DEPRECATED: Use 'eos read wazuh --ccs'",
    RunE: func(cmd *cobra.Command, args []string) error {
        logger.Warn("Command 'wazuh-ccs' is deprecated, use 'eos read wazuh --ccs' instead")
        // Forward to new implementation
    },
    Deprecated: "use 'eos read wazuh --ccs' instead",
})
```

---

## Next Steps

1. Review this plan with stakeholders
2. Implement Phase 1 (Wazuh, Vault, Database)
3. Test thoroughly
4. Document patterns for contributors
5. Roll out remaining phases
