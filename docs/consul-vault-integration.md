# Consul + Vault Integration Guide

*Last Updated: 2025-10-25*

Complete guide to the integrated Consul + Vault architecture in EOS, following HashiCorp best practices.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [ACL Configuration](#acl-configuration)
3. [Phase 0: Vault with Raft Storage](#phase-0-vault-with-raft-storage)
4. [Phase 1: Consul Secrets Engine](#phase-1-consul-secrets-engine)
5. [Phase 2: Consul KV Configuration Store](#phase-2-consul-kv-configuration-store)
6. [Phase 3: Consul Template Service](#phase-3-consul-template-service)
7. [Phase 4: Service Discovery](#phase-4-service-discovery)
8. [Integration Patterns](#integration-patterns)
9. [Troubleshooting](#troubleshooting)

## Architecture Overview

### The Right Way: Vault + Consul Separation

```
┌──────────────────────────────────────────────────────────────┐
│                        EOS Services                          │
│  (BionicGPT, Wazuh, OpenWebUI, Mattermost, etc.)          │
└────────────┬─────────────────────────┬─────────────────────┘
             │                         │
             │ Secrets                 │ Config
             │ (Vault Agent)           │ (Consul Template)
             │                         │
    ┌────────▼────────┐       ┌───────▼────────┐
    │     Vault       │       │     Consul     │
    │  (Raft Storage) │◄──────│  (Service Mesh)│
    │                 │Tokens │                │
    └─────────────────┘       └────────────────┘
         Secrets                   Discovery
        Encryption                 Config KV
         Rotation                   DNS/API
```

### Key Principles

1. **Vault**: Secrets only (passwords, API keys, certificates)
2. **Consul**: Configuration + Service Discovery
3. **No Circular Dependencies**: Vault uses Raft, not Consul storage
4. **Dynamic Tokens**: Vault generates short-lived Consul tokens
5. **Automated Rendering**: Consul Template combines both sources

## ACL Configuration

### Overview

**As of Eos v2.0 (2025-10-25)**, Consul ACLs are **enabled by default** for all new installations. This change improves security and enables seamless Vault-Consul integration.

### What Changed

**Before v2.0:**
```hcl
acl = {
  enabled = false
  default_policy = "allow"
}
```

**After v2.0:**
```hcl
acl = {
  enabled = true
  default_policy = "deny"  # Secure default: deny-by-default
  enable_token_persistence = true
}
```

### Why ACLs Are Required

Vault-Consul integration (`sudo eos sync --vault --consul`) requires Consul ACLs for:

1. **Secure Token Management**: Vault generates dynamic, short-lived Consul ACL tokens
2. **Access Control**: Services get minimal permissions via token-based policies
3. **Audit Trail**: Track which service accessed which Consul resources
4. **Compliance**: SOC2, PCI-DSS, HIPAA require access controls

### For New Installations

If you install Consul with Eos v2.0+, ACLs are enabled automatically:

```bash
sudo eos create consul
# ACLs: enabled = true (automatic)

sudo eos sync --vault --consul
# ACL bootstrap happens automatically
```

### For Existing Installations

If you have Consul already installed with ACLs disabled, you have two options:

#### Option 1: Automatic Enablement (Recommended)

Run the sync command - it will prompt you to enable ACLs:

```bash
sudo eos sync --vault --consul

# You'll see:
# Consul ACLs are currently DISABLED
#
# This operation will:
#   1. Backup current configuration to /etc/consul.d/consul.hcl.backup.TIMESTAMP
#   2. Modify /etc/consul.d/consul.hcl to enable ACLs
#   3. Restart Consul service (brief downtime)
#   4. Continue with Vault-Consul sync
#
# Enable Consul ACLs automatically? [y/N]
```

Answer **y** to enable ACLs automatically. Your original configuration will be backed up.

#### Option 2: Manual Enablement

Edit the configuration manually:

```bash
# 1. Edit Consul configuration
sudo nano /etc/consul.d/consul.hcl

# 2. Change the ACL block to:
acl = {
  enabled = true
  default_policy = "deny"  # Recommended for security
  enable_token_persistence = true
}

# 3. Restart Consul
sudo systemctl restart consul

# 4. Verify Consul is healthy
consul members

# 5. Continue with sync
sudo eos sync --vault --consul
```

#### Option 3: Force Flag (No Prompts)

Use `--force` to enable ACLs without prompting:

```bash
sudo eos sync --vault --consul --force
# Automatically enables ACLs, restarts Consul, continues sync
```

### ACL Bootstrap Process

When you run `sudo eos sync --vault --consul`, the following happens:

1. **Check ACLs Enabled**: Preflight check verifies `acl.enabled = true`
2. **Bootstrap ACL System**: Creates the initial management token
3. **Store Token in Vault**: Master token stored at `secret/consul/bootstrap-token`
4. **Create Policies**: Default policies for Vault, services, read-only access
5. **Create Management Token**: Vault gets a Consul management token
6. **Enable Secrets Engine**: Vault Consul secrets engine configured
7. **Test Token Generation**: Verify dynamic token generation works

### Security Considerations

**default_policy = "deny"** means:

- **More Secure**: Services without tokens cannot access Consul
- **Explicit Permissions**: Each service gets a token with minimal permissions
- **Zero Trust**: Default deny, explicit allow

**default_policy = "allow"** (deprecated):

- **Less Secure**: Services can access Consul without tokens
- **Not Recommended**: Only use for development/testing

### Migration Path

**Existing installations** with ACLs disabled:

1. ✅ Eos will prompt you before making changes
2. ✅ Backup created automatically
3. ✅ Rollback available if Consul fails to restart
4. ✅ No data loss (KV data preserved)
5. ✅ Services continue working (anonymous policy)

**After enabling ACLs**, you may need to update services to use tokens:

```bash
# Get a token for a service
vault read consul/creds/eos-role

# Use the token
export CONSUL_HTTP_TOKEN=<token>
consul kv get config/myservice/log_level
```

### Rollback (If Needed)

If Consul fails to start after enabling ACLs:

```bash
# 1. Find your backup
ls -lh /etc/consul.d/consul.hcl.backup.*

# 2. Restore it
sudo cp /etc/consul.d/consul.hcl.backup.TIMESTAMP /etc/consul.d/consul.hcl

# 3. Restart Consul
sudo systemctl restart consul

# 4. Verify
consul members
```

### Troubleshooting

**Error: "ACL support disabled"**

This means ACLs are not enabled in your Consul configuration. Follow the enablement steps above.

**Error: "Permission denied"**

You need a valid Consul ACL token:

```bash
# Get the bootstrap token from Vault
VAULT_TOKEN=$(cat /run/eos/vault_agent_eos.token)
export CONSUL_HTTP_TOKEN=$(vault kv get -field=value secret/consul/bootstrap-token)

# Or generate a new token
export CONSUL_HTTP_TOKEN=$(vault read -field=token consul/creds/eos-role)
```

**Consul won't start after enabling ACLs**

Check logs for errors:

```bash
journalctl -u consul -n 50
```

Common issues:
- Syntax error in consul.hcl (restore backup)
- Port conflict (check with `ss -tlnp | grep 8500`)

### Documentation

- [Consul ACL System](https://developer.hashicorp.com/consul/docs/security/acl)
- [ACL Token Management](https://developer.hashicorp.com/consul/tutorials/security/access-control-setup-production)
- [ACL Policies](https://developer.hashicorp.com/consul/docs/security/acl/acl-policies)

## Phase 0: Vault with Raft Storage

### What Changed

**Before**: Vault used Consul as storage backend (circular dependency)
**After**: Vault uses Raft Integrated Storage (self-contained, HA)

### Files Modified

- `pkg/vault/install.go` - Changed default from "consul" to "raft"
- `pkg/vault/config_builder.go` - Raft first, Consul deprecated
- `pkg/vault/raft_helpers.go` - Marked as RECOMMENDED
- `cmd/create/vault.go` - Updated CLI flag defaults

### Benefits

- ✅ No external dependencies for Vault
- ✅ Built-in HA with Raft consensus
- ✅ No circular dependency with Consul
- ✅ Simpler deployment
- ✅ Recommended by HashiCorp (2020+)

### Usage

```bash
# Create Vault with Raft storage (default)
eos create vault

# Explicitly specify Raft
eos create vault --storage-backend raft

# Legacy Consul storage (deprecated)
eos create vault --storage-backend consul
```

## Phase 1: Consul Secrets Engine

### Purpose

Enable Vault to generate dynamic, short-lived Consul ACL tokens for services.

### Files Created

- `pkg/vault/consul_secrets_engine.go` (270 lines) - Core engine management
- `pkg/vault/phase9f_consul_secrets.go` (115 lines) - Lifecycle integration
- `pkg/shared/consul_tokens.go` (304 lines) - Token helpers for applications

### How It Works

1. Vault connects to Consul with management token
2. Services request Consul tokens from Vault
3. Vault generates short-lived ACL tokens (TTL: 1h default)
4. Tokens automatically rotate before expiration
5. Revoked tokens are deleted from Consul

### Usage

**Enable the engine** (done automatically during Vault install):

```bash
# The engine is enabled in Phase 9f of vault installation
# Check status:
vault read consul/config/access
```

**Request a token from your application**:

```go
import "github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

// Get a Consul token from Vault
tokenInfo, err := shared.GetConsulTokenFromVault(ctx, vaultClient, "myapp-role")

// Use the token
consulClient.SetToken(tokenInfo.Token)

// Auto-renew in background
go shared.AutoRenewConsulToken(ctx, vaultClient, tokenInfo,
    func(renewed *shared.ConsulTokenInfo) {
        consulClient.SetToken(renewed.Token)
    },
    func(err error) {
        logger.Error("Token renewal failed", zap.Error(err))
    })
```

## Phase 2: Consul KV Configuration Store

### Purpose

Store non-sensitive configuration in Consul KV for dynamic updates without redeployment.

### Files Created

- `pkg/consul/kv/manager.go` (455 lines) - CRUD operations
- `pkg/consul/kv/patterns.go` (380 lines) - Path conventions
- `pkg/consul/kv/validation.go` (474 lines) - Prevent secrets in KV
- `pkg/consul/kv/watch.go` (386 lines) - Real-time change monitoring

### Path Structure

```
config/
  ├─ eos/                    # Global EOS config
  │  ├─ log-level
  │  └─ telemetry-enabled
  │
  ├─ bionicgpt/              # Service config
  │  ├─ log_level
  │  ├─ timeouts/
  │  │  ├─ request
  │  │  └─ connection
  │  ├─ feature_flags/
  │  │  └─ enable_rag
  │  └─ endpoints/
  │     └─ wazuh
  │
  └─ environments/           # Environment overrides
     └─ production/
```

### Usage

**Write configuration**:

```go
import "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/kv"

manager := kv.NewManager(ctx, consulClient)

// Write config
err := manager.Put("config/bionicgpt/log_level", "debug")
err = manager.Put("config/bionicgpt/feature_flags/enable_rag", "true")
```

**Read configuration**:

```go
// Read with default
logLevel := manager.GetOrDefault("config/bionicgpt/log_level", "info")

// Read all service config
config, err := manager.ListValues("config/bionicgpt/")
```

**Watch for changes**:

```go
watcher := kv.NewWatcher(ctx, consulClient)

go watcher.WatchKey("config/bionicgpt/log_level", func(key, value string, exists bool) error {
    if exists {
        setLogLevel(value)
    }
    return nil
})
```

### Validation

The validation system prevents secrets from being stored in Consul KV:

- ❌ Blocks keys like `database_password`, `api_key`, `jwt_secret`
- ❌ Detects high-entropy random strings
- ❌ Detects JWT tokens, GitHub tokens, AWS keys
- ❌ Detects base64-encoded secrets
- ✅ Allows URLs, booleans, durations, numbers

## Phase 3: Consul Template Service

### Purpose

Automatically render configuration files combining Vault secrets + Consul KV config, with automatic service reload on changes.

### Files Created

- `pkg/consultemplate/constants.go` (178 lines) - Single source of truth
- `pkg/consultemplate/install.go` (537 lines) - Binary installation
- `pkg/consultemplate/config.go` (276 lines) - HCL config builder
- `pkg/consultemplate/systemd.go` (393 lines) - Service management
- `pkg/consultemplate/templates.go` (367 lines) - Template helpers
- `pkg/consultemplate/lifecycle.go` (399 lines) - Deployment orchestration

### How It Works

1. Consul Template watches Vault secrets + Consul KV
2. Renders templates when either changes
3. Writes rendered files with correct permissions
4. Executes reload command (e.g., `docker compose up -d`)
5. Runs as dedicated systemd service per application

### Usage

**Deploy consul-template for a service**:

```go
import "github.com/CodeMonkeyCybersecurity/eos/pkg/consultemplate"

lm := consultemplate.NewLifecycleManager(rc)

err := lm.Deploy(&consultemplate.DeploymentRequest{
    ServiceName: "bionicgpt",
    Description: "Configuration rendering for BionicGPT",

    // Vault secrets to include
    VaultSecrets: []string{
        "secret/bionicgpt/postgres_password",
        "secret/bionicgpt/jwt_secret",
        "secret/bionicgpt/litellm_master_key",
    },

    // Consul KV config to include
    ConsulKeys: []string{
        "config/bionicgpt/log_level",
        "config/bionicgpt/feature_flags/enable_rag",
        "config/bionicgpt/endpoints/wazuh",
    },

    // Where to render
    OutputFile: "/opt/bionicgpt/.env",
    OutputPerms: 0640,

    // What to do after rendering
    ReloadCommand: "docker compose -f /opt/bionicgpt/docker-compose.yml up -d --force-recreate",

    // Service management
    EnableService: true,
    StartService: true,
})
```

**Generated structure**:

```
/etc/consul-template.d/
  ├─ bionicgpt.hcl                  # Config
  └─ templates/
     └─ bionicgpt/
        └─ config.env.ctmpl         # Template

/etc/systemd/system/
  └─ consul-template-bionicgpt.service

/opt/bionicgpt/
  └─ .env                           # Rendered output
```

**Template syntax**:

```bash
# /etc/consul-template.d/templates/bionicgpt/config.env.ctmpl

# Secrets from Vault
POSTGRES_PASSWORD={{ with secret "secret/bionicgpt/postgres_password" }}{{ .Data.data.value }}{{ end }}
JWT_SECRET={{ with secret "secret/bionicgpt/jwt_secret" }}{{ .Data.data.value }}{{ end }}

# Config from Consul KV
LOG_LEVEL={{ key "config/bionicgpt/log_level" }}
ENABLE_RAG={{ key "config/bionicgpt/feature_flags/enable_rag" }}
WAZUH_URL={{ key "config/bionicgpt/endpoints/wazuh" }}
```

## Phase 4: Service Discovery

### Purpose

Enable EOS services to discover and connect to each other dynamically via Consul.

### Files Created

- `pkg/consul/discovery/client.go` (420 lines) - Discovery client
- `pkg/consul/discovery/helpers.go` (310 lines) - Convenience functions
- `pkg/consul/discovery/integration.go` (350 lines) - EOS integration patterns

### How It Works

Services register with Consul including:
- Service name (e.g., "vault", "bionicgpt")
- IP address and port
- Health check endpoint
- Tags and metadata

Other services discover them via:
- Consul API (programmatic)
- Consul DNS (service.service.consul)
- SRV records (port + IP)

### Usage

**Register a service**:

```go
import "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/discovery"

client, _ := discovery.NewClient(rc, consulClient)

err := client.RegisterService(&discovery.ServiceRegistration{
    Name:    "bionicgpt",
    Address: "10.0.1.5",
    Port:    7860,
    Tags:    []string{"ai", "llm", "production"},
    Meta:    map[string]string{
        "version": "1.0.0",
    },
    HealthCheck: &discovery.HealthCheck{
        Type:     discovery.HealthCheckHTTP,
        HTTP:     "http://10.0.1.5:7860/health",
        Interval: 10 * time.Second,
        Timeout:  2 * time.Second,
    },
})
```

**Discover a service**:

```go
// Find Vault instances
addresses, err := client.FindService("vault")
for _, addr := range addresses {
    fmt.Printf("Vault at %s:%d\n", addr.Address, addr.Port)
}

// Get Vault URL
vaultURL, err := client.GetServiceURL("vault", "https")
// Returns: "https://10.0.1.5:8200"

// Build database connection string
connStr, err := discovery.BuildConnectionString(rc, consulClient,
    "postgres", "myuser", "mypass", "mydb")
// Returns: "postgres://myuser:mypass@10.0.1.5:5432/mydb"
```

**Watch for service changes**:

```go
err := client.WatchService("vault", func(addresses []*discovery.ServiceAddress) {
    logger.Info("Vault instances changed", zap.Int("count", len(addresses)))
    // Update load balancer, connection pool, etc.
})
```

**DNS resolution**:

```bash
# Query Consul DNS
dig @127.0.0.1 -p 8600 vault.service.consul

# Use in applications
VAULT_ADDR=https://vault.service.consul:8200
```

## Integration Patterns

### Pattern 1: Static Secrets + Dynamic Config

**Use Case**: Service needs database password (secret) and log level (config)

**Implementation**:
1. Store password in Vault: `vault kv put secret/myservice/db_password value=...`
2. Store log level in Consul KV: `consul kv put config/myservice/log_level debug`
3. Deploy Consul Template to render .env file
4. Service reads .env on startup

**When config changes**: Consul Template re-renders → Docker restarts → New config applied

### Pattern 2: Service-to-Service Communication

**Use Case**: BionicGPT needs to connect to Wazuh for security events

**Implementation**:
1. Wazuh registers with Consul on startup
2. BionicGPT discovers Wazuh via `discovery.FindService("wazuh")`
3. BionicGPT connects using discovered IP:port
4. If Wazuh moves/restarts, BionicGPT automatically discovers new address

### Pattern 3: Zero-Touch Credential Rotation

**Use Case**: Rotate Consul ACL tokens without service restart

**Implementation**:
1. Service requests Consul token from Vault (TTL: 1h)
2. Service starts auto-renew background goroutine
3. Before expiration, Vault generates new token
4. Service automatically uses new token
5. Old token expires and is revoked

### Pattern 4: Environment-Specific Configuration

**Use Case**: Different log levels for production vs. staging

**Implementation**:
1. Global default: `consul kv put config/myservice/log_level info`
2. Staging override: `consul kv put config/environments/staging/myservice/log_level debug`
3. Production override: `consul kv put config/environments/production/myservice/log_level warn`
4. Consul Template uses environment-specific path

## Troubleshooting

### Consul Template Not Rendering

**Check service status**:
```bash
systemctl status consul-template-bionicgpt.service
journalctl -u consul-template-bionicgpt.service -n 50
```

**Check template syntax**:
```bash
consul-template -config /etc/consul-template.d/bionicgpt.hcl -dry-run
```

**Check Vault token**:
```bash
cat /run/eos/vault_agent_eos.token
VAULT_TOKEN=$(cat /run/eos/vault_agent_eos.token) vault token lookup
```

### Service Discovery Not Working

**Check Consul DNS**:
```bash
dig @127.0.0.1 -p 8600 vault.service.consul
```

**Check service registration**:
```bash
consul catalog services
consul catalog nodes -service vault
```

**Check health checks**:
```bash
consul watch -type=checks -service=vault
```

### Validation Blocking Legitimate Config

**Symptom**: Consul KV validation rejects your config value

**Solution**: File an issue to add exception pattern

**Workaround**: Store in Vault temporarily until exception added

## Migration Guide

### From Static .env Files

**Before**:
```bash
# /opt/bionicgpt/.env (static, manual updates)
POSTGRES_PASSWORD=hardcoded
LOG_LEVEL=info
```

**After**:
```bash
# Store password in Vault
vault kv put secret/bionicgpt/postgres_password value=secure123

# Store config in Consul
consul kv put config/bionicgpt/log_level info

# Deploy Consul Template
eos consultemplate deploy bionicgpt \
    --vault-secrets secret/bionicgpt/postgres_password \
    --consul-keys config/bionicgpt/log_level \
    --output /opt/bionicgpt/.env \
    --reload "docker compose up -d"
```

### From Hardcoded Service URLs

**Before**:
```go
vaultAddr := "https://10.0.1.5:8200"  // Hardcoded
```

**After**:
```go
import "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/discovery"

vaultAddr, err := discovery.GetVaultAddress(rc, consulClient)
// Returns: "https://10.0.1.5:8200" (discovered dynamically)
```

## Best Practices

1. **Secrets in Vault, Config in Consul**: Never store secrets in Consul KV
2. **Short-lived Tokens**: Use Vault-generated tokens with TTL
3. **Health Checks**: Always register health checks with services
4. **Graceful Degradation**: Handle service discovery failures gracefully
5. **Watch for Changes**: Use watch pattern for dynamic reconfiguration
6. **Tag Your Services**: Use tags for versioning and environment separation
7. **Test Failover**: Regularly test service discovery failover scenarios

## Reference Documentation

- HashiCorp Vault: https://www.vaultproject.io/docs
- HashiCorp Consul: https://www.consul.io/docs
- Consul Template: https://github.com/hashicorp/consul-template
- EOS Source: `/Users/henry/Dev/eos/`

---

*"Separate concerns: Vault for secrets, Consul for discovery, Consul Template for delivery."*
