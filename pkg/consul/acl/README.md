## Consul ACL Management

*Last Updated: 2025-10-25*

Comprehensive ACL policy and token management for Consul, providing programmatic control over access policies and authentication tokens.

## Overview

The ACL management system provides:
- **Policy Management**: Create, update, delete, and list ACL policies
- **Token Management**: Create, update, delete, clone ACL tokens
- **Policy Templates**: Pre-built policies for common use cases
- **Token-Policy Binding**: Attach/detach policies to tokens
- **Policy Validation**: Syntax validation before creating policies

## Architecture

```
ACL Management
├── PolicyManager
│   ├── CRUD Operations (Create, Read, Update, Delete, List)
│   ├── Template Rendering (Service, KV, Node, Operator, Vault, Monitoring)
│   └── Validation (HCL syntax checking)
└── TokenManager
    ├── CRUD Operations (Create, Read, Update, Delete, List)
    ├── Token Cloning
    └── Policy Attachment (Attach, Detach, List)
```

## Quick Start

### 1. Create a Policy Manager

```go
import (
    "context"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/acl"
)

ctx := context.Background()
pm, err := acl.NewPolicyManager(ctx, "shared.GetInternalHostname:8500", "management-token")
if err != nil {
    log.Fatal(err)
}
```

### 2. Create a Policy from Template

```go
// Create a Vault access policy
policy, err := pm.RenderPolicyTemplate(ctx, acl.PolicyTemplateVaultAccess, nil)
if err != nil {
    log.Fatal(err)
}

created, err := pm.CreatePolicy(ctx, policy)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Created policy: %s (ID: %s)\n", created.Name, created.ID)
```

### 3. Create a Token with Policy

```go
tm, err := acl.NewTokenManager(ctx, "shared.GetInternalHostname:8500", "management-token")
if err != nil {
    log.Fatal(err)
}

token := &acl.Token{
    Description: "Vault server token",
    Policies:    []string{created.ID},
}

createdToken, err := tm.CreateToken(ctx, token)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Token AccessorID: %s\n", createdToken.AccessorID)
fmt.Printf("Token SecretID: %s\n", createdToken.SecretID)
```

## Policy Templates

### Service Policies

```go
// Read-only service access
policy, _ := pm.RenderPolicyTemplate(ctx,
    acl.PolicyTemplateServiceRead,
    map[string]string{"service_name": "vault"})

// Read-write service access
policy, _ := pm.RenderPolicyTemplate(ctx,
    acl.PolicyTemplateServiceWrite,
    map[string]string{"service_name": "vault"})

// Or use convenience builders
policy := acl.BuildServicePolicy("vault", true) // write=true
```

### KV Store Policies

```go
// Read-only KV access
policy, _ := pm.RenderPolicyTemplate(ctx,
    acl.PolicyTemplateKVRead,
    map[string]string{"kv_path": "config/"})

// Read-write KV access
policy := acl.BuildKVPolicy("config/", true) // write=true
```

### Node Policies

```go
// Node access
policy := acl.BuildNodePolicy("vhost5", true) // write=true
```

### Operator Policy

```go
// Full operator access
policy := acl.BuildOperatorPolicy()
```

### Vault Integration Policy

```go
// Vault server access (storage + service registration)
policy := acl.BuildVaultAccessPolicy()
created, err := pm.CreatePolicy(ctx, policy)
```

Generated HCL:
```hcl
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

### Monitoring Agent Policy

```go
// Monitoring agent access
policy := acl.BuildMonitoringAgentPolicy()
```

Generated HCL:
```hcl
# Service discovery
service_prefix "" {
  policy = "read"
}

# Node information
node_prefix "" {
  policy = "read"
}

# Agent metrics
agent_prefix "" {
  policy = "read"
}

# Health check status
key_prefix "health/" {
  policy = "read"
}

# Catalog access
operator = "read"
```

## Policy Management

### Create Custom Policy

```go
policy := acl.BuildCustomPolicy(
    "custom-app-policy",
    "Access for my application",
    `
service "my-app" {
  policy = "write"
}

key_prefix "my-app/" {
  policy = "write"
}

session_prefix "" {
  policy = "write"
}
`,
)

created, err := pm.CreatePolicy(ctx, policy)
```

### Read Policy

```go
// By ID
policy, err := pm.ReadPolicy(ctx, "policy-id")

// By name
policy, err := pm.ReadPolicyByName(ctx, "vault-access")
```

### Update Policy

```go
policy.Rules = `
service "vault" {
  policy = "write"
}
# Updated rules
`

updated, err := pm.UpdatePolicy(ctx, policy.ID, policy)
```

### Delete Policy

```go
err := pm.DeletePolicy(ctx, "policy-id")
```

### List All Policies

```go
policies, err := pm.ListPolicies(ctx)
for _, policy := range policies {
    fmt.Printf("Policy: %s (ID: %s)\n", policy.Name, policy.ID)
}
```

## Token Management

### Create Token

```go
token := &acl.Token{
    Description: "My application token",
    Policies:    []string{"policy-id-1", "policy-id-2"},
    Local:       false, // Global token (replicated across datacenters)
}

created, err := tm.CreateToken(ctx, token)

// Save the SecretID securely - this is the actual token!
fmt.Printf("Secret Token: %s\n", created.SecretID)
```

### Create Token with Expiration

```go
import "time"

token := &acl.Token{
    Description:   "Temporary token",
    Policies:      []string{"policy-id"},
    ExpirationTTL: 24 * time.Hour,
}

created, err := tm.CreateToken(ctx, token)
```

### Read Token

```go
token, err := tm.ReadToken(ctx, "accessor-id")
```

### Update Token

```go
token.Description = "Updated description"
token.Policies = append(token.Policies, "new-policy-id")

updated, err := tm.UpdateToken(ctx, token.AccessorID, token)
```

### Delete Token

```go
err := tm.DeleteToken(ctx, "accessor-id")
```

### Clone Token

```go
cloned, err := tm.CloneToken(ctx, "source-accessor-id", "Cloned token")
```

### List All Tokens

```go
tokens, err := tm.ListTokens(ctx)
for _, token := range tokens {
    fmt.Printf("Token: %s (%d policies)\n",
        token.Description, len(token.Policies))
}
```

## Token-Policy Management

### Attach Policy to Token

```go
err := tm.AttachPolicy(ctx, "token-accessor-id", "policy-id")
```

### Detach Policy from Token

```go
err := tm.DetachPolicy(ctx, "token-accessor-id", "policy-id")
```

### List Token's Policies

```go
policies, err := tm.ListTokenPolicies(ctx, "token-accessor-id")
for _, policy := range policies {
    fmt.Printf("Policy: %s\n  Rules:\n%s\n", policy.Name, policy.Rules)
}
```

## Complete Example: Vault Setup

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/acl"
)

func setupVaultACL() error {
    ctx := context.Background()

    // Create managers
    pm, err := acl.NewPolicyManager(ctx, "shared.GetInternalHostname:8500", "bootstrap-token")
    if err != nil {
        return err
    }

    tm, err := acl.NewTokenManager(ctx, "shared.GetInternalHostname:8500", "bootstrap-token")
    if err != nil {
        return err
    }

    // 1. Create Vault access policy
    policy := acl.BuildVaultAccessPolicy()
    createdPolicy, err := pm.CreatePolicy(ctx, policy)
    if err != nil {
        return fmt.Errorf("failed to create policy: %w", err)
    }

    log.Printf("Created policy: %s (ID: %s)", createdPolicy.Name, createdPolicy.ID)

    // 2. Create token for Vault
    token := &acl.Token{
        Description: "Vault server token",
        Policies:    []string{createdPolicy.ID},
        Local:       false, // Replicate across datacenters
    }

    createdToken, err := tm.CreateToken(ctx, token)
    if err != nil {
        return fmt.Errorf("failed to create token: %w", err)
    }

    log.Printf("Created token:")
    log.Printf("  AccessorID: %s", createdToken.AccessorID)
    log.Printf("  SecretID: %s", createdToken.SecretID)
    log.Printf("\nConfigure Vault with:")
    log.Printf("  export CONSUL_HTTP_TOKEN=%s", createdToken.SecretID)

    return nil
}

func main() {
    if err := setupVaultACL(); err != nil {
        log.Fatal(err)
    }
}
```

## Policy Validation

All policies are validated before creation/update:

```go
policy := &acl.Policy{
    Name: "test-policy",
    Rules: `
    service "web" {
      policy = "read"
    }
    `, // Missing closing brace
}

err := pm.ValidatePolicy(ctx, policy)
// Returns: "policy rules contain invalid HCL syntax"
```

## Error Handling

All operations follow ASSESS → INTERVENE → EVALUATE pattern:

```go
policy, err := pm.CreatePolicy(ctx, policy)
if err != nil {
    // Errors include context
    log.Printf("Policy creation failed: %v\n", err)
    // Examples:
    // - "policy validation failed: policy name is required"
    // - "failed to create policy vault-access: ACL support disabled"
    // - "policy xyz not found after creation" (EVALUATE failure)
}
```

## Integration with Vault

### Update vault/service.go

Replace file-based Vault registration:

```go
// OLD: pkg/consul/vault/service.go
func GenerateServiceConfig(rc *eos_io.RuntimeContext) error {
    // Writes JSON file to /etc/consul.d/vault-service.json
}

// NEW: Use registry + ACL
func RegisterVaultWithACL(rc *eos_io.RuntimeContext) error {
    ctx := rc.Ctx

    // 1. Create ACL policy
    pm, _ := acl.NewPolicyManager(ctx, "shared.GetInternalHostname:8500", aclToken)
    policy := acl.BuildVaultAccessPolicy()
    createdPolicy, _ := pm.CreatePolicy(ctx, policy)

    // 2. Create token
    tm, _ := acl.NewTokenManager(ctx, "shared.GetInternalHostname:8500", aclToken)
    token := &acl.Token{
        Description: "Vault server",
        Policies:    []string{createdPolicy.ID},
    }
    createdToken, _ := tm.CreateToken(ctx, token)

    // 3. Register service using registry (from P1 Task 1)
    reg, _ := registry.NewServiceRegistry(ctx, "shared.GetInternalHostname:8500")
    service := &registry.ServiceRegistration{
        ID:   "vault-" + hostname,
        Name: "vault",
        // ...
    }
    reg.RegisterService(ctx, service)

    // 4. Configure Vault with token
    vaultConfig := fmt.Sprintf(`
storage "consul" {
  address = "shared.GetInternalHostname:8500"
  path    = "vault/"
  token   = "%s"
}
`, createdToken.SecretID)

    return nil
}
```

## Testing

Mockable interfaces for testing:

```go
type MockPolicyManager struct {
    Policies map[string]*acl.Policy
}

func (m *MockPolicyManager) CreatePolicy(ctx context.Context, policy *acl.Policy) (*acl.Policy, error) {
    policy.ID = "mock-policy-id"
    m.Policies[policy.ID] = policy
    return policy, nil
}

// Use in tests
pm := &MockPolicyManager{Policies: make(map[string]*acl.Policy)}
policy := acl.BuildVaultAccessPolicy()
created, _ := pm.CreatePolicy(ctx, policy)
```

## Troubleshooting

### ACLs Not Enabled

```bash
$ eos consul acl policy list
Error: ACL support disabled
```

Solution: Enable ACLs in Consul configuration:
```hcl
acl {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
}
```

### Token Permission Denied

```bash
Error: failed to create policy: Permission denied
```

Solution: Ensure management token has `acl = "write"` permission.

### Policy Not Found After Creation

This indicates a Consul cluster issue (split brain, network partition). Check:
- Consul cluster health: `consul members`
- Raft status: `consul operator raft list-peers`

## Authentication Methods (Not Yet Implemented)

**Status**: Infrastructure ready, implementation planned for future release

### What Are Authentication Methods?

Authentication methods are **alternative ways to obtain Consul ACL tokens** without manually creating and distributing them. They enable automated, secure token acquisition for services and humans.

### Why Are They Grayed Out in the Consul UI?

When you see "Access Controls", "Policies", "Roles", and "Auth Methods" grayed out in the Consul UI, it means **ACLs are not enabled**. Consul runs in "open mode" by default where anyone can do anything.

**Good news**: In Eos, ACLs are **ENABLED BY DEFAULT** with secure settings:
```hcl
acl {
  enabled = true
  default_policy = "deny"  # Secure by default
  enable_token_persistence = true
}
```

After `eos create consul`, all ACL features should be active in the UI.

### Three Types of Authentication Methods

#### 1. Kubernetes Auth Method
**Use case**: Automatically authenticate Kubernetes Pods using service account tokens

**How it works**:
- Consul validates Kubernetes JWT tokens via the TokenReview API
- Service account metadata (namespace, name, UID) becomes trusted identity
- Binding rules map K8s identities to Consul roles/policies

**Benefits**:
- No manual token distribution to containers
- Tokens rotate automatically with K8s service accounts
- Integrates with existing K8s RBAC

**Example workflow**:
```bash
# 1. Create auth method (admin operation)
consul acl auth-method create \
  -type kubernetes \
  -name k8s-cluster \
  -config @k8s-config.json

# 2. Create binding rule (admin operation)
consul acl binding-rule create \
  -method k8s-cluster \
  -bind-type service \
  -bind-name vault \
  -selector 'serviceaccount.name==vault'

# 3. Pod authenticates automatically (no manual tokens!)
# K8s service account JWT → Consul validates → Returns Consul token
```

**Current Eos status**: ❌ Not implemented (future enhancement)

#### 2. JWT Auth Method
**Use case**: Machine-to-machine authentication with pre-existing JWTs

**How it works**:
- Consul validates JWTs using local keys or OIDC Discovery
- Claims in JWT are mapped to Consul roles/policies
- Headless authentication (no browser required)

**Benefits**:
- Integrates with existing identity systems (Keycloak, Auth0, etc.)
- No Consul-specific credential distribution
- Automated token issuance for CI/CD pipelines

**Example workflow**:
```bash
# 1. Create JWT auth method
consul acl auth-method create \
  -type jwt \
  -name ci-pipeline \
  -config @jwt-config.json

# 2. CI system gets JWT from identity provider
# 3. CI exchanges JWT for Consul token
consul login -method=ci-pipeline -bearer-token-file=jwt.token
```

**Current Eos status**: ❌ Not implemented (future enhancement)

#### 3. OIDC Auth Method (Consul Enterprise only)
**Use case**: Human operators logging in via SSO (Okta, Azure AD, Google Workspace)

**How it works**:
- Browser-based OAuth2/OIDC flow
- Operators authenticate with corporate SSO
- OIDC claims map to Consul roles/policies

**Benefits**:
- No manual Consul token distribution to staff
- Leverage existing SSO/MFA infrastructure
- Centralized user management

**Example workflow**:
```bash
# 1. Create OIDC auth method (admin operation)
consul acl auth-method create \
  -type oidc \
  -name corporate-sso \
  -config @oidc-config.json

# 2. User logs in via browser
consul login -method=corporate-sso
# Opens browser, redirects to Okta, returns with Consul token
```

**Current Eos status**: ❌ Not implemented (requires Consul Enterprise)

### Why Doesn't Eos Implement These Yet?

**Short answer**: Complexity and use case prioritization

**Long answer**:
1. **Kubernetes auth method**: Requires K8s cluster integration
   - Need to detect K8s API server endpoint
   - Manage K8s service account for Consul
   - Configure TokenReview permissions
   - Handle multiple K8s clusters
   - **Complexity**: Medium-High

2. **JWT auth method**: Requires identity provider integration
   - Need to configure JWT verification keys
   - Support OIDC Discovery or manual key configuration
   - Manage claim mappings
   - Handle key rotation
   - **Complexity**: Medium

3. **OIDC auth method**: Requires Consul Enterprise + SSO setup
   - Consul Enterprise license required
   - SSO provider configuration (Okta, Azure AD, etc.)
   - OAuth2 callback URL configuration
   - Browser-based flow (not CLI-friendly)
   - **Complexity**: High

**Current Eos philosophy**: Focus on foundational ACL system first
- ✅ ACL enablement by default
- ✅ Bootstrap token management
- ✅ Policy and token CRUD operations
- ✅ Vault integration for secure token storage
- ⏳ Auth methods coming in future releases

### Workaround: Manual Auth Method Setup

If you need auth methods NOW, you can configure them manually:

```bash
# Example: Kubernetes auth method
consul acl auth-method create \
  -type kubernetes \
  -name k8s-prod \
  -description "Production K8s cluster" \
  -kubernetes-host "https://k8s-api:6443" \
  -kubernetes-ca-cert @ca.crt \
  -kubernetes-service-account-jwt @sa-token.jwt

# Create binding rule
consul acl binding-rule create \
  -method k8s-prod \
  -bind-type service \
  -bind-name "web-\${serviceaccount.name}" \
  -selector 'serviceaccount.namespace==production'
```

See [Consul Auth Method documentation](https://developer.hashicorp.com/consul/docs/security/acl/auth-methods) for details.

### Roadmap: When Will Eos Support Auth Methods?

**Planned implementation order**:
1. **Phase 1** (Current): Basic ACL system
   - ✅ Policy management
   - ✅ Token management
   - ✅ Bootstrap token recovery
   - ✅ Vault integration

2. **Phase 2** (Q2 2025): JWT auth method
   - Auto-detect Vault JWT backend
   - Configure Consul JWT auth method
   - Map Vault roles to Consul policies
   - **Use case**: Vault-authenticated services get Consul tokens

3. **Phase 3** (Q3 2025): Kubernetes auth method
   - Detect if running in K8s cluster
   - Auto-configure K8s auth method
   - Create binding rules for common patterns
   - **Use case**: K8s Pods get Consul tokens automatically

4. **Phase 4** (Future): OIDC auth method
   - Consul Enterprise detection
   - Interactive OIDC provider configuration
   - CLI-based login flow
   - **Use case**: Operators log in with SSO

### How to Know When Auth Methods Are Available

**In Consul UI**: After ACLs are enabled, you'll see:
- ✅ Access Controls (active)
- ✅ Tokens (active)
- ✅ Policies (active)
- ✅ Roles (active)
-  Auth Methods (active but empty if none configured)

**In Eos**: Check for new commands:
```bash
# Future commands (not yet available)
eos consul acl auth-method create --type kubernetes
eos consul acl auth-method list
eos consul acl binding-rule create
```

**Sign up for updates**: Follow [Eos GitHub](https://github.com/CodeMonkeyCybersecurity/eos) for release announcements

### References

- [Consul Auth Methods Overview](https://developer.hashicorp.com/consul/docs/security/acl/auth-methods)
- [Kubernetes Auth Method](https://developer.hashicorp.com/consul/docs/security/acl/auth-methods/kubernetes)
- [JWT Auth Method](https://developer.hashicorp.com/consul/docs/security/acl/auth-methods/jwt)
- [OIDC Auth Method](https://developer.hashicorp.com/consul/docs/security/acl/auth-methods/oidc)

## Future Enhancements

- [ ] Role management (groups of policies)
- [ ] Auth method integration (Kubernetes, JWT, OIDC) - See "Authentication Methods" section above
- [ ] Binding rules for automatic policy attachment
- [ ] Policy namespaces (Consul Enterprise)
- [ ] Token self-service operations
- [ ] Automated token rotation
