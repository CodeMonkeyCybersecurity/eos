# Vault Enablement Idempotency Design

*Last Updated: 2025-10-15*

## Problem Statement

Running `sudo eos create vault` multiple times (e.g., after failures) prompts the user for the same information repeatedly:
- "Enable Userpass authentication?" - even if already enabled
- "Enter password for Eos Vault user:" - even if user already exists
- "Enable AppRole authentication?" - even if already configured
- Agent configuration - even if already set up

This violates idempotency principles and wastes user time.

## Current State Analysis

### What Works ✅
- Low-level functions ARE idempotent:
  - `EnsureUserpassUser()` checks if user exists before creating
  - `EnableUserpassAuth()` handles "path already in use" gracefully
  - `EnsureAppRole()` checks for existing credentials
  - AppRole files are only written if needed

### What's Broken 
- **Prompts happen before checks**: `lifecycle2_enable.go:121-134`
- **No state persistence**: No record of which enablement phases completed
- **User has to remember**: Must answer "no" to avoid re-prompting
- **Password prompted too early**: Before checking if user exists

## Design Solution

### Approach 1: Query Vault State (RECOMMENDED)

**Principle**: Don't ask the user what Vault already knows.

#### Implementation

1. **Check auth methods before prompting**:
```go
// Before prompting, check if userpass is already configured
func isUserpassConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error) {
    // Check if auth method is mounted
    auths, err := client.Sys().ListAuth()
    if err != nil {
        return false, err
    }
    if _, exists := auths["userpass/"]; !exists {
        return false, nil
    }

    // Check if eos user exists
    secret, err := client.Logical().Read(shared.EosUserpassPath)
    if err != nil {
        return false, err
    }
    return secret != nil, nil
}
```

2. **Modify enablement flow**:
```go
// Step 10a: Configure userpass auth
userpassConfigured, err := isUserpassConfigured(rc, client)
if err != nil {
    log.Warn("Failed to check userpass status", zap.Error(err))
}

if userpassConfigured {
    log.Info("terminal prompt: Userpass authentication already configured - skipping")
} else if interaction.PromptYesNo(rc.Ctx, "Enable Userpass authentication?", false) {
    if err := PhaseEnableUserpass(rc, client, log, ""); err != nil {
        return logger.LogErrAndWrap(rc, "enable Userpass", err)
    }
}
```

3. **Add rotation option**:
```go
if userpassConfigured {
    log.Info("terminal prompt: Userpass authentication already configured")
    if interaction.PromptYesNo(rc.Ctx, "Rotate password?", false) {
        // Prompt for new password and update
    }
}
```

### Approach 2: State File Tracking

**Principle**: Persist enablement state to disk.

#### State File Structure
```json
{
  "vault_initialized": true,
  "vault_unsealed": true,
  "kv_v2_enabled": true,
  "userpass_enabled": true,
  "userpass_user_created": true,
  "approle_enabled": true,
  "approle_configured": true,
  "entity_created": true,
  "policies_written": true,
  "audit_enabled": true,
  "agent_configured": false,
  "last_updated": "2025-10-15T14:30:00Z"
}
```

Location: `/var/lib/eos/secret/vault_enablement_state.json`

#### Implementation
```go
type VaultEnablementState struct {
    VaultInitialized    bool      `json:"vault_initialized"`
    VaultUnsealed       bool      `json:"vault_unsealed"`
    KVv2Enabled         bool      `json:"kv_v2_enabled"`
    UserpassEnabled     bool      `json:"userpass_enabled"`
    UserpassUserCreated bool      `json:"userpass_user_created"`
    AppRoleEnabled      bool      `json:"approle_enabled"`
    AppRoleConfigured   bool      `json:"approle_configured"`
    EntityCreated       bool      `json:"entity_created"`
    PoliciesWritten     bool      `json:"policies_written"`
    AuditEnabled        bool      `json:"audit_enabled"`
    AgentConfigured     bool      `json:"agent_configured"`
    LastUpdated         time.Time `json:"last_updated"`
}

func LoadEnablementState(rc *eos_io.RuntimeContext) (*VaultEnablementState, error) {
    path := filepath.Join(shared.SecretsDir, "vault_enablement_state.json")
    data, err := os.ReadFile(path)
    if os.IsNotExist(err) {
        return &VaultEnablementState{}, nil // Fresh state
    }
    if err != nil {
        return nil, fmt.Errorf("read state file: %w", err)
    }

    var state VaultEnablementState
    if err := json.Unmarshal(data, &state); err != nil {
        return nil, fmt.Errorf("parse state file: %w", err)
    }
    return &state, nil
}

func (s *VaultEnablementState) Save() error {
    s.LastUpdated = time.Now()
    path := filepath.Join(shared.SecretsDir, "vault_enablement_state.json")
    data, err := json.MarshalIndent(s, "", "  ")
    if err != nil {
        return fmt.Errorf("marshal state: %w", err)
    }

    // Write with proper permissions
    return eos_unix.WriteFile(context.Background(), path, data, 0600, "vault")
}
```

### Approach 3: Hybrid (BEST)

Combine both approaches:
1. **Query Vault** for ground truth (auth methods, users, entities)
2. **State file** for Eos-specific tracking (agent config, which prompts shown)
3. **File-based checks** for credentials (role_id, secret_id exist)

#### Benefits
- **Vault queries**: Authoritative for Vault state
- **State file**: Tracks Eos-specific enablement progress
- **File checks**: Fast local verification without API calls
- **Self-healing**: If state file is deleted, Vault queries recover

## Implementation Plan

### Phase 1: Add State Checking Functions (P1 - CRITICAL)

Create `pkg/vault/enablement_state.go`:

```go
// IsUserpassConfigured checks if userpass auth is mounted and eos user exists
func IsUserpassConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error)

// IsAppRoleConfigured checks if approle auth is mounted and eos-approle exists
func IsAppRoleConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error)

// IsEntityConfigured checks if eos entity exists with aliases
func IsEntityConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error)

// IsAuditConfigured checks if file audit backend is enabled
func IsAuditConfigured(rc *eos_io.RuntimeContext, client *api.Client) (bool, error)

// IsAgentConfigured checks if Vault Agent config and service exist
func IsAgentConfigured(rc *eos_io.RuntimeContext) (bool, error)
```

### Phase 2: Modify Enablement Flow (P1 - CRITICAL)

Update `pkg/vault/lifecycle2_enable.go`:

```go
// Step 10a: Configure userpass auth
userpassConfigured, err := IsUserpassConfigured(rc, client)
if err != nil {
    log.Warn("Failed to check userpass status, will prompt", zap.Error(err))
    userpassConfigured = false // Default to prompting on error
}

if userpassConfigured {
    log.Info("terminal prompt: ✓ Userpass authentication already configured")
    if interaction.PromptYesNo(rc.Ctx, "Rotate eos user password?", false) {
        password, err := crypto.PromptPassword(rc, "Enter NEW password for Eos Vault user:")
        if err != nil {
            return logger.LogErrAndWrap(rc, "prompt password", err)
        }
        // Update existing user
        if err := UpdateUserpassPassword(rc, client, password); err != nil {
            return logger.LogErrAndWrap(rc, "rotate password", err)
        }
    }
} else {
    if interaction.PromptYesNo(rc.Ctx, "Enable Userpass authentication?", false) {
        if err := PhaseEnableUserpass(rc, client, log, ""); err != nil {
            return logger.LogErrAndWrap(rc, "enable Userpass", err)
        }
    }
}
```

### Phase 3: Add Force Flags (P2 - IMPORTANT)

Add CLI flags to `cmd/create/secrets.go`:

```go
var (
    forceUserpass bool
    forceAppRole  bool
    forceAgent    bool
)

func init() {
    createVaultCmd.Flags().BoolVar(&forceUserpass, "force-userpass", false,
        "Force re-configuration of userpass auth even if already set up")
    createVaultCmd.Flags().BoolVar(&forceAppRole, "force-approle", false,
        "Force re-configuration of AppRole auth even if already set up")
    createVaultCmd.Flags().BoolVar(&forceAgent, "force-agent", false,
        "Force re-configuration of Vault Agent even if already set up")
}
```

### Phase 4: Add State File (P3 - RECOMMENDED)

For tracking Eos-specific state that Vault doesn't know about:

```go
type VaultEnablementState struct {
    AgentConfigWritten bool      `json:"agent_config_written"`
    AgentServiceSet up bool      `json:"agent_service_setup"`
    FirstRunCompleted  bool      `json:"first_run_completed"`
    LastUpdated        time.Time `json:"last_updated"`
}
```

## User Experience Flow

### First Run
```
$ sudo eos create vault
[... installation phases ...]
Enable Userpass authentication? [y/N]: y
Enter password for Eos Vault user: ********
✓ Userpass authentication configured

Enable AppRole authentication? [y/N]: y
✓ AppRole authentication configured

Enable Vault Agent? [y/N]: y
✓ Vault Agent configured
```

### Second Run (After Failure During Agent Config)
```
$ sudo eos create vault
[... installation phases ...]
✓ Userpass authentication already configured
  Rotate eos user password? [y/N]: n

✓ AppRole authentication already configured
  Regenerate AppRole credentials? [y/N]: n

Enable Vault Agent? [y/N]: y
✓ Vault Agent configured
```

### Third Run (All Complete)
```
$ sudo eos create vault
[... installation phases ...]
✓ Userpass authentication already configured
✓ AppRole authentication already configured
✓ Vault Agent already configured
✓ Vault is fully configured and operational
```

## Security Considerations

1. **Password rotation**: Provide explicit rotation option instead of silent updates
2. **Credential regeneration**: AppRole secret_id rotation should be explicit
3. **Audit trail**: Log all configuration checks and decisions
4. **Fail-safe defaults**: On query errors, default to prompting (safer than skipping)

## Testing Requirements

1. **Idempotency test**: Run `eos create vault` twice, verify no re-prompts
2. **Partial failure recovery**: Fail during agent config, re-run, verify resume
3. **Force flags**: Verify `--force-userpass` triggers re-configuration
4. **Password rotation**: Verify rotation works and updates all credential stores

## Implementation Priority

**P0 (BREAKING)**: N/A
**P1 (CRITICAL)**:
- Add state checking functions
- Modify enablement flow to check before prompting
- Add password rotation option

**P2 (IMPORTANT)**:
- Add force flags for re-configuration
- Add regenerate credentials option for AppRole

**P3 (RECOMMENDED)**:
- Add state file for Eos-specific tracking
- Add comprehensive enablement status command

## Related Issues

- Audit log permission error (FIXED in commit 6e839d37)
- Key verification mismatch (FIXED in commit 50fceebe)

---

*"Solve problems once, encode in Eos, never solve again."*
