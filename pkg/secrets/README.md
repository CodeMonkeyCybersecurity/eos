# Secrets Management Interface

*Last Updated: 2025-01-22*

Unified secret management interface for Eos with Vault and file backends.

## Philosophy

**Solve it once, solve it well**: This interface provides a single, consistent API for secret management across the entire Eos codebase. Use these functions instead of direct Vault/backend access.

## Features

### Core Functionality (P0)
- ✅ **StoreSecret()** - Store individual secrets with automatic backend selection
- ✅ **GetSecret()** - Retrieve secrets with type safety
- ✅ **UpdateSecret()** - Update existing secrets (validates existence first)
- ✅ **StoreSecretWithMetadata()** - Store secrets with TTL, owner, rotation policy, compliance metadata
- ✅ **GetSecretWithMetadata()** - Retrieve secrets along with their metadata
- ✅ **DeleteSecret()** - Remove individual secrets atomically
- ✅ **ListSecrets()** - Enumerate all secrets for a service
- ✅ **SecretExists()** - Check existence without retrieving value

### Security Features
- ✅ Fail-closed in production (no file backend fallback)
- ✅ Centralized Vault client (respects VAULT_SKIP_VERIFY, TLS settings)
- ✅ Diagnostic logging with token capabilities, policies, TTL
- ✅ Permission denied errors include remediation hints
- ✅ Metadata NOT encrypted (audit-logged, never put sensitive data in metadata)

### Backend Support
- **Vault (Production)**: Uses KV v2 with custom metadata support
- **File (Dev/Test Only)**: JSON files at `/opt/eos/secrets/` (metadata ignored)

## Quick Start

### Basic Usage

```go
// 1. Initialize secret manager
envConfig, _ := environment.DiscoverEnvironment(rc)
secretManager, _ := secrets.NewSecretManager(rc, envConfig)

// 2. Store a secret
err := secretManager.StoreSecret("bionicgpt", "api_key", "sk-abc123", secrets.SecretTypeAPIKey)

// 3. Retrieve a secret
apiKey, err := secretManager.GetSecret("bionicgpt", "api_key")

// 4. Update a secret
err = secretManager.UpdateSecret("bionicgpt", "api_key", "sk-new456", secrets.SecretTypeAPIKey)

// 5. Delete a secret
err = secretManager.DeleteSecret("bionicgpt", "old_key")

// 6. List all secrets for a service
secretNames, err := secretManager.ListSecrets("bionicgpt")
// Returns: ["api_key", "postgres_password", "jwt_secret"]

// 7. Check if secret exists
if secretManager.SecretExists("bionicgpt", "api_key") {
    // Secret exists
}
```

### Advanced Usage with Metadata (TTL, Compliance)

```go
// Store Azure API key with 90-day TTL and compliance metadata
metadata := &secrets.SecretMetadata{
    TTL:         "90d",              // Rotate after 90 days
    CreatedBy:   "eos create bionicgpt",
    CreatedAt:   "2025-01-22T10:30:00Z",
    Purpose:     "Azure OpenAI API integration",
    Owner:       "bionicgpt",
    RotateAfter: "90d",
    Custom: map[string]string{
        "endpoint": "https://myazure.openai.azure.com",
        "model":    "gpt-4",
        "region":   "eastus",
    },
}

err := secretManager.StoreSecretWithMetadata(
    "bionicgpt",
    "azure_api_key",
    apiKey,
    secrets.SecretTypeAPIKey,
    metadata,
)

// Retrieve secret with metadata
value, metadata, err := secretManager.GetSecretWithMetadata("bionicgpt", "azure_api_key")
if err != nil {
    return err
}

logger.Info("Secret metadata",
    zap.String("ttl", metadata.TTL),
    zap.String("purpose", metadata.Purpose),
    zap.String("endpoint", metadata.Custom["endpoint"]))
```

### Batch Secret Generation (Existing Pattern)

```go
// Define all required secrets upfront
requiredSecrets := map[string]secrets.SecretType{
    "postgres_password": secrets.SecretTypePassword,
    "jwt_secret":        secrets.SecretTypeJWT,
    "api_key":           secrets.SecretTypeAPIKey,
}

// Get or generate all secrets (idempotent)
serviceSecrets, err := secretManager.GetOrGenerateServiceSecrets("bionicgpt", requiredSecrets)
if err != nil {
    return err
}

// Access secrets with type safety
postgresPassword := serviceSecrets.GetString("postgres_password")
jwtSecret := serviceSecrets.GetString("jwt_secret")
apiKey := serviceSecrets.GetString("api_key")

// Or with error handling
postgresPassword, err := serviceSecrets.GetStringOrError("postgres_password")
if err != nil {
    return fmt.Errorf("missing postgres password: %w", err)
}
```

## Storage Paths

### Unified Path Format
All secrets stored at: `services/{environment}/{service}`

Example:
- Development: `services/development/bionicgpt`
- Production: `services/production/bionicgpt`

### Secret Bundle Structure
Secrets stored as map with type metadata:
```json
{
  "azure_api_key": "sk-abc123",
  "azure_api_key_type": "api_key",
  "postgres_password": "p@ssw0rd",
  "postgres_password_type": "password",
  "jwt_secret": "jwt-secret-value",
  "jwt_secret_type": "jwt"
}
```

### Metadata Storage (Vault KV v2 Only)
Metadata stored at: `secret/metadata/services/{environment}/{service}`

Example metadata:
```json
{
  "custom_metadata": {
    "ttl": "90d",
    "created_by": "eos create bionicgpt",
    "created_at": "1706023800",
    "purpose": "Azure OpenAI API integration",
    "owner": "bionicgpt",
    "rotate_after": "90d",
    "custom_endpoint": "https://myazure.openai.azure.com",
    "custom_model": "gpt-4"
  }
}
```

## Secret Types

```go
const (
    SecretTypePassword SecretType = "password"  // Strong password (32 chars, alphanumeric)
    SecretTypeAPIKey   SecretType = "api_key"   // API key (32 chars, alphanumeric)
    SecretTypeToken    SecretType = "token"     // Generic token (32 chars, alphanumeric)
    SecretTypeJWT      SecretType = "jwt"       // JWT secret (32+ chars, alphanumeric)
)
```

All secrets generated using `pkg/crypto` functions (alphanumeric only for maximum compatibility).

## Use Cases

### 1. Azure OpenAI Integration (BionicGPT)

```go
// Store Azure API key with metadata
metadata := &secrets.SecretMetadata{
    TTL:       "90d",
    Purpose:   "Azure OpenAI API integration",
    Owner:     "bionicgpt",
    CreatedBy: "eos create bionicgpt",
    Custom: map[string]string{
        "endpoint": "https://myazure.openai.azure.com",
        "model":    "gpt-4",
    },
}

err := secretManager.StoreSecretWithMetadata(
    "bionicgpt",
    "azure_api_key",
    apiKey,
    secrets.SecretTypeAPIKey,
    metadata,
)
```

### 2. Backup Token Storage

```go
// Backup tokens don't expire but rotate after each use
metadata := &secrets.SecretMetadata{
    TTL:         "never",
    RotateAfter: "on_use",
    Purpose:     "Offsite backup encryption",
    Owner:       "restic",
}

err := secretManager.StoreSecretWithMetadata(
    "restic",
    "backup_token",
    token,
    secrets.SecretTypeToken,
    metadata,
)
```

### 3. Authentik SSO Secrets

```go
// Store Authentik client secret with custom metadata
metadata := &secrets.SecretMetadata{
    TTL:       "365d",
    Purpose:   "Authentik SSO integration",
    Owner:     "authentik",
    CreatedBy: "eos create authentik",
    Custom: map[string]string{
        "client_id":    "bionicgpt-client",
        "redirect_uri": "https://bionicgpt.example.com/auth/callback",
        "scopes":       "openid profile email",
    },
}

err := secretManager.StoreSecretWithMetadata(
    "authentik",
    "client_secret",
    clientSecret,
    secrets.SecretTypeToken,
    metadata,
)
```

### 4. Database Credentials

```go
// Store database password without metadata (simple case)
err := secretManager.StoreSecret(
    "postgres",
    "admin_password",
    password,
    secrets.SecretTypePassword,
)

// Later retrieve it
dbPassword, err := secretManager.GetSecret("postgres", "admin_password")
```

## Migration from Old Patterns

### Before (Broken - Direct Backend Access)

```go
// OLD: Azure package used custom path
vaultPath := fmt.Sprintf("services/%s/%s/azure_openai_api_key", env, service)
backend.Store(vaultPath, map[string]interface{}{"value": apiKey})

// OLD: BionicGPT retrieved differently
secrets, _ := secretManager.GetOrGenerateServiceSecrets("bionicgpt", map[...])
apiKey := secrets.Secrets["azure_api_key"].(string) // PATH MISMATCH!
```

### After (Fixed - Unified Interface)

```go
// NEW: Both use same interface
secretManager.StoreSecret("bionicgpt", "azure_api_key", apiKey, secrets.SecretTypeAPIKey)

// NEW: Retrieval is consistent
apiKey, _ := secretManager.GetSecret("bionicgpt", "azure_api_key")
```

## Error Handling

### Permission Denied Errors

Includes remediation hints:

```
failed to store secret in Vault at services/production/bionicgpt: permission denied

HINT: The Vault policy may be missing service secrets access.
Run this command to update Vault policies:
  sudo eos update vault --update-policies

Then restart Vault Agent to get a new token:
  sudo systemctl restart vault-agent-eos
```

### Storage Failure (P0 FIX)

**OLD BEHAVIOR (BROKEN)**: Secrets generated but not persisted, function returns success
```go
if err := sm.backend.Store(secretPath, secrets.Secrets); err != nil {
    logger.Error("Failed to store secrets", zap.Error(err))
    // Don't fail - secrets are generated, just not persisted  ❌ DANGER!
}
return secrets, nil  // ❌ Returns success even if storage failed!
```

**NEW BEHAVIOR (FIXED)**: Fail fast if storage fails
```go
if err := sm.backend.Store(secretPath, secrets.Secrets); err != nil {
    logger.Error("Failed to store secrets in backend", zap.Error(err))
    return nil, fmt.Errorf("failed to persist secrets to backend at %s: %w", secretPath, err)
}
```

## Compliance & Audit

### SOC2/PCI-DSS/HIPAA Requirements

Use metadata to track compliance requirements:

```go
metadata := &secrets.SecretMetadata{
    TTL:       "90d",                    // Rotation requirement
    CreatedBy: "admin@example.com",      // Accountability
    CreatedAt: time.Now().Format(time.RFC3339),
    Purpose:   "PCI-DSS cardholder data encryption",
    Owner:     "payment-service",
    RotateAfter: "90d",                  // Automatic rotation policy
    Custom: map[string]string{
        "compliance_framework": "PCI-DSS",
        "data_classification":  "restricted",
        "approved_by":          "security-team@example.com",
    },
}
```

### Audit Trail

Vault automatically logs all secret access (read/write/delete) in audit logs.
Metadata stored in `custom_metadata` is also audit-logged but NOT encrypted.

**SECURITY WARNING**: Never put sensitive data in metadata!

## Testing

### Unit Tests

```go
func TestSecretStorage(t *testing.T) {
    // Set up file backend for testing
    os.Setenv("GO_ENV", "test")
    os.Setenv("EOS_SECRET_BACKEND", "file")

    rc := eos_io.NewRuntimeContext(context.Background())
    envConfig := &environment.EnvironmentConfig{
        Environment: "test",
    }

    secretManager, err := secrets.NewSecretManager(rc, envConfig)
    require.NoError(t, err)

    // Test store
    err = secretManager.StoreSecret("test-service", "test-key", "test-value", secrets.SecretTypePassword)
    require.NoError(t, err)

    // Test retrieve
    value, err := secretManager.GetSecret("test-service", "test-key")
    require.NoError(t, err)
    assert.Equal(t, "test-value", value)

    // Test exists
    assert.True(t, secretManager.SecretExists("test-service", "test-key"))

    // Test delete
    err = secretManager.DeleteSecret("test-service", "test-key")
    require.NoError(t, err)
    assert.False(t, secretManager.SecretExists("test-service", "test-key"))
}
```

## Troubleshooting

### "Vault backend required in production but initialization failed"

**Cause**: Vault not available in production environment
**Fix**: Ensure Vault is running and `VAULT_ADDR`, `VAULT_TOKEN` are set

### "failed to write metadata to secret/metadata/services/..."

**Cause**: Vault token lacks metadata write permissions
**Fix**: Run `sudo eos update vault --update-policies`

### "Secret exists in memory but lost on restart"

**Cause**: Silent storage failure bug (FIXED in this update)
**Fix**: Update to latest eos version with P0 fix

## Architecture Compliance (CLAUDE.md)

✅ **Business logic in pkg/**: All secret operations in `pkg/secrets/`
✅ **Structured logging**: Uses `otelzap.Ctx(rc.Ctx)` throughout
✅ **A→I→E pattern**: All methods follow Assess → Intervene → Evaluate
✅ **RuntimeContext**: All operations use `*eos_io.RuntimeContext`
✅ **Error context**: Errors include remediation hints
✅ **Security**: Fail-closed in production, diagnostic logging, no hardcoded credentials

## Reference Implementation

See existing usage:
- BionicGPT: `pkg/bionicgpt/install.go`
- Azure OpenAI: `pkg/azure/openai.go` (will be migrated)
- Vault integration: `pkg/vault/phase13_write_agent_config.go`

## Future Enhancements (P2-P3)

- [ ] Automatic rotation workflows
- [ ] Secret version history (Vault KV v2 supports this)
- [ ] Secret dependencies and atomic multi-secret operations
- [ ] TTL enforcement (check metadata TTL, warn on expiration)
- [ ] Centralized rotation scheduler

---

*"Solve it once, solve it well, never solve it again."*
