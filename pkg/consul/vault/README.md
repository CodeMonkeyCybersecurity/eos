## Vault-Consul Integration

*Last Updated: 2025-10-23*

Comprehensive Vault-Consul integration with automatic ACL policy creation, token lifecycle management, and SDK-based service registration.

## Overview

This package provides:
- **Automatic Service Registration**: Register Vault in Consul service catalog
- **ACL Policy Management**: Auto-create Vault access policies
- **Token Lifecycle**: Create and manage ACL tokens for Vault
- **Version Detection**: Automatically detect Vault version and storage backend
- **Health Monitoring**: Configure health checks for Vault
- **Configuration Generation**: Generate Vault storage config with Consul token

## Bugs Fixed (P1)

This implementation fixes the following issues identified in the adversarial review:

1. ✅ **Hardcoded Version**: Now detects actual Vault version via `vault version`
2. ✅ **File-Based Registration**: Replaced with SDK-based `registry.ServiceRegistry`
3. ✅ **No Token Lifecycle**: Implements full token creation and management
4. ✅ **Hardcoded Paths**: Uses `consul.ConsulVaultServiceConfig` and other constants
5. ✅ **Storage Backend Detection**: Automatically detects Consul/File/Raft storage

## Migration from Old Approach

### Before (File-Based)
```go
// OLD: pkg/consul/vault/service.go
func GenerateServiceConfig(rc *eos_io.RuntimeContext) error {
    // Writes JSON file to /etc/consul.d/vault-service.json
    // Hardcoded version: "1.15.0"
    // No ACL token management
    // Requires Consul reload
}
```

### After (SDK-Based)
```go
// NEW: pkg/consul/vault/integration.go
integration, _ := vault.NewVaultIntegration(rc, &vault.IntegrationConfig{
    ConsulAddress:    "127.0.0.1:8500",
    ConsulACLToken:   managementToken,
    VaultAddress:     "https://127.0.0.1:8200",
    AutoCreatePolicy: true,
    AutoCreateToken:  true,
})

result, _ := integration.RegisterVault(ctx, config)
// - Detects actual Vault version
// - Creates ACL policy automatically
// - Creates ACL token automatically
// - Registers via SDK (no file, no reload)
```

## Quick Start

### 1. Basic Registration (No ACLs)

```go
import (
    "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/vault"
)

config := &vault.IntegrationConfig{
    ConsulAddress: "127.0.0.1:8500",
    VaultAddress:  "https://127.0.0.1:8200",
}

integration, err := vault.NewVaultIntegration(rc, config)
if err != nil {
    log.Fatal(err)
}

result, err := integration.RegisterVault(ctx, config)
if err != nil {
    log.Fatal(err)
}

log.Printf("Vault registered as service: %s\n", result.ServiceID)
```

### 2. Full Integration with ACLs

```go
config := &vault.IntegrationConfig{
    ConsulAddress:    "127.0.0.1:8500",
    ConsulACLToken:   "management-token-here",
    VaultAddress:     "https://127.0.0.1:8200",
    AutoCreatePolicy: true,  // Create Vault access policy
    AutoCreateToken:  true,  // Create ACL token for Vault
    TokenTTL:         0,     // No expiration (or use 24*time.Hour)
}

integration, err := vault.NewVaultIntegration(rc, config)
result, err := integration.RegisterVault(ctx, config)

// Result contains everything you need
log.Printf("Policy ID: %s\n", result.PolicyID)
log.Printf("Token Accessor: %s\n", result.TokenAccessorID)
log.Printf("Token Secret: %s\n", result.TokenSecretID)

// Configure Vault with the token
vaultConfig := result.GetVaultStorageConfig("127.0.0.1:8500")
log.Printf("Vault Config:\n%s\n", vaultConfig)
```

### 3. Complete Setup Example

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/vault"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func setupVaultConsulIntegration() error {
    ctx := context.Background()
    rc := &eos_io.RuntimeContext{Ctx: ctx}

    // Get Consul management token (from bootstrap or environment)
    consulToken := os.Getenv("CONSUL_HTTP_TOKEN")
    if consulToken == "" {
        return fmt.Errorf("CONSUL_HTTP_TOKEN required for ACL setup")
    }

    // Configure integration
    config := &vault.IntegrationConfig{
        ConsulAddress:    "127.0.0.1:8500",
        ConsulACLToken:   consulToken,
        VaultAddress:     "https://127.0.0.1:8200",
        AutoCreatePolicy: true,
        AutoCreateToken:  true,
    }

    // Create integration
    integration, err := vault.NewVaultIntegration(rc, config)
    if err != nil {
        return fmt.Errorf("failed to create integration: %w", err)
    }

    // Register Vault
    result, err := integration.RegisterVault(ctx, config)
    if err != nil {
        return fmt.Errorf("failed to register Vault: %w", err)
    }

    // Display results
    log.Println("✅ Vault registered with Consul")
    log.Printf("   Service ID: %s\n", result.ServiceID)
    log.Printf("   ACL Policy: %s (%s)\n", result.PolicyName, result.PolicyID)
    log.Printf("   ACL Token: %s\n", result.TokenAccessorID)

    // Save token for Vault configuration
    log.Println("\n📝 Configure Vault with:")
    log.Printf("   export CONSUL_HTTP_TOKEN=%s\n", result.TokenSecretID)

    // Generate Vault config
    vaultConfig := result.GetVaultStorageConfig("127.0.0.1:8500")
    log.Println("\n📄 Add to /etc/vault.d/vault.hcl:")
    log.Println(vaultConfig)

    return nil
}

func main() {
    if err := setupVaultConsulIntegration(); err != nil {
        log.Fatal(err)
    }
}
```

## Features

### Automatic Version Detection

The integration automatically detects the Vault version:

```go
// Internal method (called automatically)
version, err := integration.getVaultVersion()
// Returns: "1.15.0" (or actual installed version)

// Version is included in service tags and metadata
Tags: ["version-1.15.0", ...]
Meta: {"version": "1.15.0"}
```

### Storage Backend Detection

Automatically detects the storage backend:

```go
// Detects from /etc/vault.d/vault.hcl:
// - "consul" if storage "consul" { ... }
// - "file" if storage "file" { ... }
// - "raft" if storage "raft" { ... }
// - "unknown" if not detected

Tags: ["storage-consul", ...]
Meta: {"storage_type": "consul"}
```

### ACL Policy Created

When `AutoCreatePolicy: true`, the following policy is created:

```hcl
# Policy Name: vault-access

# Vault storage backend
key_prefix "vault/" {
  policy = "write"
}

# Service registration
service "vault" {
  policy = "write"
}

# Health checks
agent_prefix "" {
  policy = "read"
}

# Node catalog for HA coordination
node_prefix "" {
  policy = "read"
}

# Session management for HA locking
session_prefix "" {
  policy = "write"
}
```

### Service Registration

The service is registered with:

```json
{
  "ID": "vault-vhost5",
  "Name": "vault",
  "Address": "127.0.0.1",
  "Port": 8200,
  "Tags": [
    "active",
    "tls",
    "storage-consul",
    "primary",
    "eos-managed",
    "version-1.15.0"
  ],
  "Meta": {
    "version": "1.15.0",
    "storage_type": "consul",
    "instance": "vhost5",
    "environment": "production",
    "eos_managed": "true"
  },
  "Check": {
    "ID": "vault-health",
    "Name": "Vault HTTPS Health",
    "HTTP": "https://127.0.0.1:8200/v1/sys/health?standbyok=true&perfstandbyok=true",
    "Interval": "10s",
    "Timeout": "5s",
    "TLSSkipVerify": true
  },
  "Weights": {
    "Passing": 10,
    "Warning": 1
  }
}
```

## Deregistration

Clean up Vault registration and ACL resources:

```go
// Basic deregistration (keep ACL resources)
err := integration.DeregisterVault(ctx, "vault-vhost5", false)

// Full cleanup (remove ACL policy and tokens)
err := integration.DeregisterVault(ctx, "vault-vhost5", true)
```

## Integration with Eos Commands

### Update cmd/create/consul.go

Replace file-based Vault registration:

```go
// OLD
import "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/vault"
if err := vault.GenerateServiceConfig(rc); err != nil {
    return err
}

// NEW
import (
    consulvault "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/vault"
)

config := &consulvault.IntegrationConfig{
    ConsulAddress:    fmt.Sprintf("127.0.0.1:%d", shared.PortConsul),
    ConsulACLToken:   managementToken, // If ACLs enabled
    VaultAddress:     os.Getenv("VAULT_ADDR"),
    AutoCreatePolicy: aclsEnabled,
    AutoCreateToken:  aclsEnabled,
}

integration, err := consulvault.NewVaultIntegration(rc, config)
if err != nil {
    return err
}

result, err := integration.RegisterVault(rc.Ctx, config)
if err != nil {
    return err
}

// Save token to Vault config or environment
if result.TokenSecretID != "" {
    log.Info("Vault ACL token created",
        zap.String("accessor_id", result.TokenAccessorID))
    // TODO: Configure Vault with token
}
```

## Configuration Generation

Generate Vault storage configuration:

```go
result, _ := integration.RegisterVault(ctx, config)

// Get storage config
storageConfig := result.GetVaultStorageConfig("127.0.0.1:8500")

// Write to Vault config file
configPath := "/etc/vault.d/vault.hcl"
// ... (read existing config, append storage block, write back)
```

Output:
```hcl
storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault/"
  token   = "s.abc123def456..."
}
```

## Token Lifecycle Management

The token created for Vault can be:

**No Expiration** (default):
```go
config := &vault.IntegrationConfig{
    AutoCreateToken: true,
    TokenTTL:        0, // Never expires
}
```

**With TTL**:
```go
config := &vault.IntegrationConfig{
    AutoCreateToken: true,
    TokenTTL:        24 * time.Hour, // Expires in 24 hours
}
```

**Token Rotation** (see P1 Task 4):
```go
// Manually rotate token
tm, _ := acl.NewTokenManager(ctx, "127.0.0.1:8500", managementToken)

// Read current token
oldToken, _ := tm.ReadToken(ctx, result.TokenAccessorID)

// Create new token with same policy
newToken := &acl.Token{
    Description: "Vault server ACL token (rotated)",
    Policies:    oldToken.Policies,
}
created, _ := tm.CreateToken(ctx, newToken)

// Update Vault config with new token
// Delete old token
tm.DeleteToken(ctx, oldToken.AccessorID)
```

## Error Handling

All operations follow ASSESS → INTERVENE → EVALUATE pattern:

```go
result, err := integration.RegisterVault(ctx, config)
if err != nil {
    // Specific errors:
    // - "vault address not provided and VAULT_ADDR not set"
    // - "failed to create service registry: ..."
    // - "consul ACL token required for policy/token creation"
    // - "failed to create Vault ACL policy: ..."
    // - "failed to register Vault service: ..."
    log.Fatal(err)
}
```

## Troubleshooting

### Vault Version Not Detected

```bash
Error: failed to detect Vault version
```

**Solution**: Ensure `vault` binary is in PATH:
```bash
which vault
# /usr/local/bin/vault

vault version
# Vault v1.15.0
```

### Storage Backend Unknown

```bash
Warning: Failed to detect Vault storage backend, using 'unknown'
```

**Solution**: Ensure Vault config file exists at standard location:
- `/etc/vault.d/vault.hcl`
- `/etc/vault/vault.hcl`

### ACL Token Creation Failed

```bash
Error: failed to create Vault ACL token: Permission denied
```

**Solution**: Ensure management token has `acl = "write"` permission:
```bash
consul acl token read -id=<token-accessor-id>
# Verify policies include acl write permission
```

## Benefits Over File-Based Approach

| Feature | File-Based (OLD) | SDK-Based (NEW) |
|---------|------------------|-----------------|
| **Version** | Hardcoded "1.15.0" | Auto-detected |
| **ACL Policy** | Manual creation | Automatic |
| **ACL Token** | Manual creation | Automatic |
| **Registration** | File + reload | SDK (immediate) |
| **Storage Config** | Manual | Generated |
| **Error Handling** | Silent failures | Explicit errors |
| **Verification** | Manual | Automatic EVALUATE |
| **Constants** | Hardcoded paths | Centralized |

## Future Enhancements

- [ ] Automatic token rotation (P1 Task 4)
- [ ] Multi-datacenter registration
- [ ] Vault HA coordination
- [ ] Consul Connect integration
- [ ] Token renewal monitoring
- [ ] Health check failure alerts
