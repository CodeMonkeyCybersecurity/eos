# Vault Auto-Authentication via Agent Token

*Last Updated: 2025-10-21*

## Problem Statement

Commands like `sudo eos create bionicgpt` were failing with:

```
ERROR Failed to store API key in Vault {"error": "... Code: 403. Errors: * permission denied"}
```

**Root Cause:** `GetVaultClient()` was not loading any authentication token, expecting users to manually set `VAULT_TOKEN` environment variable. This broke the "it just works" principle.

## Solution: Central Authentication

We now have **ONE central authentication mechanism** in `pkg/vault/client_context.go:GetVaultClient()` that:

1. Checks if `VAULT_TOKEN` environment variable is set (explicit override)
2. If not, **automatically loads the Vault Agent token** from `/run/eos/vault_agent_eos.token`
3. Uses this everywhere in the codebase through the centralized function

### Implementation

**File:** [pkg/vault/client_context.go:52-74](pkg/vault/client_context.go#L52)

```go
// CRITICAL P0: Auto-load Vault Agent token if VAULT_TOKEN not set
// This fixes "permission denied" errors when running eos commands
// that need to write to Vault (e.g., eos create bionicgpt)
if client.Token() == "" {
    // Try to load token from Vault Agent
    tokenPath := shared.AgentToken // /run/eos/vault_agent_eos.token
    if tokenData, err := os.ReadFile(tokenPath); err == nil {
        token := strings.TrimSpace(string(tokenData))
        if token != "" {
            client.SetToken(token)
            logger.Debug("Loaded Vault token from agent",
                zap.String("token_path", tokenPath),
                zap.Int("token_length", len(token)))
        } else {
            logger.Warn("Vault Agent token file is empty",
                zap.String("token_path", tokenPath))
        }
    } else {
        logger.Debug("Could not read Vault Agent token (may not be available yet)",
            zap.String("token_path", tokenPath),
            zap.Error(err))
    }
}
```

## Token Hierarchy

The authentication follows this priority order:

1. **Explicit VAULT_TOKEN** environment variable (highest priority)
   - User override for specific operations
   - Example: `VAULT_TOKEN=hvs.xyz eos create bionicgpt`

2. **Vault Agent token** (automatic fallback)
   - Located at `/run/eos/vault_agent_eos.token`
   - Managed by `vault-agent-eos.service`
   - **This is the default for all eos commands**

3. **No token** (graceful degradation)
   - Logs debug message, doesn't fail
   - Allows commands that don't need Vault to continue

## Where This Is Used

`GetVaultClient()` is called from:

### Direct Vault Operations
- `pkg/secrets/manager.go` → `NewVaultBackend()` → All secret operations
- `pkg/vault/*.go` → All Vault configuration, initialization, unsealing

### Service Installations Using Secrets
- `pkg/azure/openai.go` → Storing Azure OpenAI API keys (BionicGPT, etc.)
- `cmd/create/bionicgpt.go` → PostgreSQL passwords, JWT secrets
- `cmd/create/openwebui.go` → LiteLLM master key
- `cmd/create/temporal.go` → Database credentials
- Any service using `secretManager.GetOrGenerateServiceSecrets()`

### Status and Health Checks
- `pkg/servicestatus/vault.go` → Vault health monitoring
- `cmd/read/status.go` → System status checks

## Vault Agent Token Lifecycle

### Created During Vault Installation
1. Vault installation creates AppRole authentication
2. `vault-agent-eos.service` starts and authenticates
3. Agent writes token to `/run/eos/vault_agent_eos.token`
4. Token is automatically renewed by the agent

### Permissions
```bash
-rw-r----- 1 root eos /run/eos/vault_agent_eos.token
```

- Owned by `root:eos`
- Readable by root and eos group
- **This is why `sudo eos` commands work** - root can read the token

### Token Capabilities

The Vault Agent token has these policies (configured during vault installation):

```hcl
# Allow read/write to services secrets
path "secret/data/services/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow read/write to service-specific paths
path "secret/data/{{identity.entity.aliases.AUTH_METHOD_ACCESSOR.metadata.service}}/*" {
  capabilities = ["create", "read", "update", "delete"]
}
```

This allows services to:
- Store their own secrets
- Read secrets for their dependencies
- Update secrets during rotation

## Debugging Authentication Issues

### Check Token Existence
```bash
sudo cat /run/eos/vault_agent_eos.token
```

Should output a token starting with `hvs.` (Vault 1.10+) or `s.` (older versions).

### Check Token Validity
```bash
export VAULT_ADDR=https://vhost11:8200
export VAULT_SKIP_VERIFY=1
export VAULT_TOKEN=$(sudo cat /run/eos/vault_agent_eos.token)
vault token lookup
```

Should show token capabilities and TTL.

### Check Vault Agent Status
```bash
sudo systemctl status vault-agent-eos
sudo journalctl -u vault-agent-eos -n 50
```

### Enable Debug Logging
```bash
# Temporary debug logging
sudo eos create bionicgpt --log-level=debug

# Or set in environment
export EOS_LOG_LEVEL=debug
sudo -E eos create bionicgpt
```

Look for:
```
DEBUG Loaded Vault token from agent {"token_path": "/run/eos/vault_agent_eos.token", "token_length": 95}
```

## Migration Guide

### Before This Fix

Services had to manually handle authentication:

```go
// OLD PATTERN - Don't use
client, err := api.NewClient(api.DefaultConfig())
if err != nil {
    return err
}
// Token was never set - commands would fail!
```

### After This Fix

All code uses centralized authentication:

```go
// NEW PATTERN - Use everywhere
client, err := vault.GetVaultClient(rc)
if err != nil {
    return fmt.Errorf("failed to get vault client: %w", err)
}
// Token is automatically loaded - it just works!
```

## Related Files

- [pkg/vault/client_context.go](pkg/vault/client_context.go) - **Central authentication (start here!)**
- [pkg/secrets/manager.go](pkg/secrets/manager.go) - Uses GetVaultClient for all secret operations
- [pkg/shared/vault_agent.go](pkg/shared/vault_agent.go) - Agent token path constant
- [pkg/vault/phase13_write_agent_config.go](pkg/vault/phase13_write_agent_config.go) - Creates agent config
- [pkg/vault/phase14_start_agent.go](pkg/vault/phase14_start_agent.go) - Starts agent service

## Testing

### Build Verification
```bash
CGO_ENABLED=0 go build -o /tmp/eos-build ./cmd/
```

✅ **Result:** Build succeeds

### Functional Test
```bash
# This should now work without VAULT_TOKEN
sudo eos create bionicgpt

# Should see in logs:
# DEBUG Loaded Vault token from agent
# INFO Storing Azure OpenAI API key in Vault {"path": "..."}
# INFO ✓ Azure OpenAI API key stored in Vault successfully
```

## Security Considerations

### Why This Is Safe

1. **Token file permissions** - Only root and eos group can read
2. **Vault Agent manages lifecycle** - Auto-renewal, no manual rotation needed
3. **Scoped policies** - Agent token only has access to `secret/data/services/*`, not root secrets
4. **Explicit override available** - Users can still set `VAULT_TOKEN` for specific operations
5. **Audit logging** - All Vault operations are logged

### Why This Is Better Than Before

**Before:** Users had to:
- Manually extract root token from `.vault_init_output.json`
- Set `VAULT_TOKEN` environment variable
- Remember to do this for every command
- Risk leaking root token in shell history

**After:**
- `sudo eos create bionicgpt` → **IT JUST WORKS**
- No manual token management
- Uses scoped agent token (principle of least privilege)
- No root token exposure

## Troubleshooting

### "Could not read Vault Agent token"

**Symptoms:**
```
DEBUG Could not read Vault Agent token (may not be available yet)
ERROR Failed to store API key in Vault {"error": "... Code: 403"}
```

**Causes:**
1. Vault Agent service not running
2. Token file doesn't exist (fresh install)
3. Permissions issue on token file

**Resolution:**
```bash
# Check agent status
sudo systemctl status vault-agent-eos

# Restart if needed
sudo systemctl restart vault-agent-eos

# Wait a few seconds for token to be written
sleep 5

# Verify token exists
sudo ls -la /run/eos/vault_agent_eos.token

# Try command again
sudo eos create bionicgpt
```

### "Vault Agent token file is empty"

**Symptoms:**
```
WARN Vault Agent token file is empty
```

**Cause:** Agent started but hasn't authenticated yet (race condition)

**Resolution:**
```bash
# Wait for agent to authenticate
sleep 10

# Check agent logs
sudo journalctl -u vault-agent-eos -n 20
```

Look for: `renewed auth token`

## Future Improvements

1. **Token caching** - Cache token in RuntimeContext to avoid repeated file reads
2. **Fallback to root token** - If agent token unavailable during install, try root token from init output
3. **Health check** - Verify token validity before operations (call `/v1/auth/token/lookup-self`)
4. **Rotation handling** - Detect token rotation and update client automatically

## Compliance

✅ **P0 Rules:**
- Uses centralized constants (`shared.AgentToken`)
- All logging uses `otelzap.Ctx(rc.Ctx)`
- No hardcoded paths (uses `shared.AgentToken = "/run/eos/vault_agent_eos.token"`)
- Follows error handling best practices

✅ **Philosophy:**
- **Human centric** - "It just works", no manual token management
- **Evidence based** - Solves real authentication failure
- **Sustainable** - ONE central function, used everywhere
- **Solves problem once** - Never manually set `VAULT_TOKEN` again

---

*"Solve problems once, encode in Eos, never solve again."*
