# API Client Framework - Design Summary

*Last Updated: 2025-11-03*

**Status**: Architecture Complete, Implementation Pending
**Author**: Henry (with Claude)
**Compliance**: CLAUDE.md P0, Authentik 2025.10, ROADMAP.md

---

## Executive Summary

This framework provides a **declarative, YAML-driven approach** to mapping OpenAPI/REST APIs to human-friendly CLI commands in Eos. Instead of writing one-off wrappers for each API endpoint, we define resources and operations in YAML and let the framework handle:

- **HTTP request construction**
- **Parameter validation**
- **Interactive prompting** (CLAUDE.md P0 #13 human-centric pattern)
- **Output formatting** (table, JSON, YAML, CSV)
- **Error handling with remediation**

**Key Benefit**: Add new API endpoints with **~10 lines of YAML** (no Go code required).

---

## Design Philosophy

### 1. Human-Centric (CLAUDE.md P0)

**Problem**: Raw API calls are not user-friendly:
```bash
# Hard to remember, error-prone
curl -X GET "https://auth.example.com/api/v3/core/users/?is_superuser=false" \
  -H "Authorization: Bearer token_here"
```

**Solution**: Plain-language CLI commands:
```bash
# Intuitive, self-documenting
eos list authentik users --superuser=false
```

**Interactive Fallback**: Missing parameters prompt the user (informed consent):
```bash
$ eos create authentik user
→ Username is required for user creation.
→ Enter username: alice
→ Email: alice@example.com
→ User type (internal/external/service_account) [internal]: internal
✓ Created user alice (UUID: 123e4567-e89b-12d3-a456-426614174000)
```

### 2. Declarative Configuration

**Problem**: Writing Cobra commands for each API endpoint is repetitive:
- Parse flags
- Validate inputs
- Build HTTP request
- Handle errors
- Format output

**Solution**: Define resources in YAML, framework handles the rest:

```yaml
# pkg/authentik/api_definition.yaml
resources:
  users:
    path: /api/v3/core/users
    operations:
      list:
        method: GET
        filters:
          - name: is_superuser
            type: boolean
```

**Result**: `eos list authentik users --superuser=true` works automatically.

### 3. Compliance with Existing Patterns

**Authentik 2025.10**:
- Uses `pkg/authentik/unified_client.go` for HTTP transport
- Consolidates clients (CLAUDE.md HTTP Client Consolidation Rule)
- Shares TLS config, timeouts, retry logic

**CLAUDE.md P0 Rules**:
- All operations use `*eos_io.RuntimeContext`
- Structured logging via `otelzap.Ctx(rc.Ctx)`
- Secrets from Consul/Vault (never hardcoded)
- Interactive prompting via `pkg/interaction/required_flag.go`

**ROADMAP.md Alignment**:
- Supports Hecate Configuration Management (Phase 0)
- Enables Authentik Client Consolidation (2025-11 → 2026-01)
- Extensible to Wazuh, Caddy, other services

### 4. Generic and Extensible

**Service-Agnostic**: Works for any OpenAPI/REST API:
- Authentik
- Wazuh
- Caddy Admin API
- Future services

**Minimal Boilerplate**: Add new service with:
1. Create `pkg/[service]/api_definition.yaml` (~100 lines)
2. Implement `HTTPClient` interface (if custom transport needed)
3. Add commands (`cmd/list/[service].go`, `cmd/read/[service].go`, etc.)

**No code generation required** - YAML drives behavior at runtime.

---

## HTTP Method → Eos Command Mapping

| HTTP Method | OpenAPI Op | Eos Verb | Pattern | Example |
|------------|-----------|----------|---------|---------|
| **GET** (single) | `get` | `read` | `eos read [svc] [res] [id]` | `eos read authentik user {uuid}` |
| **GET** (list) | `list` | `list` | `eos list [svc] [res] [--filters]` | `eos list authentik users --type=external` |
| **POST** | `create` | `create` | `eos create [svc] [res] [--fields]` | `eos create authentik user --username=alice` |
| **PATCH** | `update` | `update` | `eos update [svc] [res] [id] [--field=val]` | `eos update authentik user {uuid} --type=internal` |
| **PUT** | `replace` | `update --replace` | `eos update [svc] [res] [id] --replace` | `eos update authentik flow {uuid} --replace` |
| **DELETE** | `delete` | `delete` | `eos delete [svc] [res] [id]` | `eos delete authentik user {uuid}` |

**Consistency**: All services use same verb pattern (learn once, use everywhere).

---

## Architecture Components

### 1. API Definition Files (`pkg/[service]/api_definition.yaml`)

**Purpose**: Declarative specification of API resources, operations, parameters.

**Example** (Authentik users resource):

```yaml
service: authentik
version: 2025.10
auth:
  type: bearer_token
  token_consul_key: "service/hecate/secrets/authentik_token"
  base_url_consul_key: "service/hecate/config/authentik_url"

resources:
  users:
    path: /api/v3/core/users
    description: "Manage Authentik users"

    operations:
      list:
        method: GET
        description: "List all users"
        filters:
          - name: is_superuser
            type: boolean
            description: "Filter by superuser status"
          - name: type
            type: string
            values: [internal, external, service_account]
            description: "Filter by user type"
        output_fields: [pk, username, email, type, is_active]

      get:
        method: GET
        path: /api/v3/core/users/{pk}
        description: "Get user details by UUID"
        params:
          - name: pk
            type: uuid
            required: true
            description: "User UUID"
        output_fields: [pk, username, email, type, groups]

      create:
        method: POST
        description: "Create a new user"
        fields:
          - name: username
            type: string
            required: true
            description: "Unique username"
          - name: email
            type: email
            required: true
            description: "User email address"
          - name: type
            type: string
            default: internal
            values: [internal, external, service_account]
        returns: "User UUID"

      update:
        method: PATCH
        path: /api/v3/core/users/{pk}
        description: "Update user attributes"
        params:
          - name: pk
            type: uuid
            required: true
        fields:
          - name: type
            type: string
            values: [internal, external, service_account]
          - name: is_active
            type: boolean

      delete:
        method: DELETE
        path: /api/v3/core/users/{pk}
        description: "Delete a user"
        params:
          - name: pk
            type: uuid
            required: true
        confirm: true  # Requires --force flag
        confirm_message: "This will permanently delete user {pk}. Continue?"

    subresources:
      permissions:
        path: /api/v3/core/users/{pk}/permissions
        description: "User's effective permissions"
        operations:
          list:
            method: GET
            description: "List user permissions"
```

**Key Features**:
- **Nested resources**: `eos read authentik user {pk} permissions`
- **Type validation**: `uuid`, `email`, `boolean`, `enum`
- **Interactive prompts**: Help text, default values
- **Security**: Confirmation prompts for destructive ops

### 2. Runtime Executor (`pkg/apiclient/executor.go`)

**Purpose**: Loads YAML definition, executes operations, formats output.

**Key Methods**:

```go
type Executor struct {
    definition *APIDefinition       // Parsed from YAML
    httpClient HTTPClient            // Service-specific transport
    rc         *eos_io.RuntimeContext // For logging, tracing, secrets
}

// List resources with filters
func (e *Executor) List(ctx context.Context, resource string, filters map[string]interface{}) (*ListResult, error)

// Get single resource
func (e *Executor) Get(ctx context.Context, resource string, params map[string]interface{}) (*GetResult, error)

// Create new resource
func (e *Executor) Create(ctx context.Context, resource string, fields map[string]interface{}) (*CreateResult, error)

// Update existing resource
func (e *Executor) Update(ctx context.Context, resource string, params map[string]interface{}, fields map[string]interface{}) (*UpdateResult, error)

// Delete resource
func (e *Executor) Delete(ctx context.Context, resource string, params map[string]interface{}) (*DeleteResult, error)
```

**Flow**:
1. Load API definition from YAML
2. Validate operation exists for resource
3. Validate parameters/fields against definition
4. Build HTTP request (method, path, body)
5. Delegate to `HTTPClient.DoRequest()`
6. Parse response
7. Format and return result

### 3. Service-Specific HTTP Clients (Adapter Pattern)

**Interface**:

```go
type HTTPClient interface {
    DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error)
}
```

**Implementations**:
- **Authentik**: `pkg/authentik/unified_client.go` (already exists)
- **Wazuh**: `pkg/wazuh/client.go` (future)
- **Caddy**: `pkg/caddy/client.go` (future)

**Why Adapter Pattern?**:
- **Reuses existing clients**: Authentik unified client works as-is
- **Allows customization**: Services can override retry logic, auth, etc.
- **Maintains separation**: Framework doesn't know about TLS configs, API quirks

**Example Integration** (Authentik):

```go
// pkg/authentik/unified_client.go already implements DoRequest()
// No changes needed - just pass it to executor

executor, err := apiclient.NewExecutor(rc, "authentik")
// Executor internally calls:
//   client := authentik.NewUnifiedClient(baseURL, token)
//   executor.httpClient = client
```

### 4. CLI Commands (`cmd/list/authentik.go`, etc.)

**Pattern** (orchestration only, follows CLAUDE.md architecture):

```go
// cmd/list/authentik.go
var authentikCmd = &cobra.Command{
    Use:   "authentik [resource]",
    Short: "List Authentik resources",
    Long: "List Authentik resources with filters.\n\n" +
          "Examples:\n" +
          "  eos list authentik users\n" +
          "  eos list authentik users --type=external\n" +
          "  eos list authentik groups --member={uuid}",
    RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
        logger := otelzap.Ctx(rc.Ctx)

        if len(args) < 1 {
            return fmt.Errorf("resource type required (users, groups, flows, etc.)")
        }

        resource := args[0]

        // Load executor with Authentik definition
        executor, err := apiclient.NewExecutor(rc, "authentik")
        if err != nil {
            return fmt.Errorf("failed to initialize Authentik API client: %w", err)
        }

        // Extract filters from flags
        filters, err := extractFiltersFromFlags(cmd, executor.Definition(), resource)
        if err != nil {
            return err
        }

        logger.Info("Listing Authentik resources",
            zap.String("resource", resource),
            zap.Any("filters", filters))

        // Execute operation (ALL business logic in pkg/apiclient)
        results, err := executor.List(rc.Ctx, resource, filters)
        if err != nil {
            return fmt.Errorf("failed to list %s: %w", resource, err)
        }

        // Format and display output
        format, _ := cmd.Flags().GetString("format")
        return apiclient.FormatOutput(rc, results, format)
    }),
}

func init() {
    // Add standard flags (auto-generated from API definition would be ideal)
    authentikCmd.Flags().Bool("superuser", false, "Filter by superuser status")
    authentikCmd.Flags().String("type", "", "Filter by user type (internal, external, service_account)")
    authentikCmd.Flags().String("format", "table", "Output format (table, json, yaml, csv)")

    listCmd.AddCommand(authentikCmd)
}
```

**File size**: ~100 lines per command (CLAUDE.md architecture enforcement: cmd/ = orchestration ONLY).

### 5. Output Formatting (`pkg/apiclient/output.go`)

**Formats**:
- **table**: Human-readable, aligned columns (default)
- **json**: Machine-readable, full structure
- **yaml**: Human-readable, structured
- **csv**: Spreadsheet-compatible

**Example Output** (`eos list authentik users --format=table`):

```
PK                                    USERNAME        EMAIL                       TYPE      ACTIVE
123e4567-e89b-12d3-a456-426614174000  alice_wonderland alice@cybermonkey.net.au   external  true
234e5678-e89b-12d3-a456-426614174001  bob_builder     bob@cybermonkey.net.au     external  true
```

**Example Output** (`eos list authentik users --format=json`):

```json
{
  "items": [
    {
      "pk": "123e4567-e89b-12d3-a456-426614174000",
      "username": "alice_wonderland",
      "email": "alice@cybermonkey.net.au",
      "type": "external",
      "is_active": true
    },
    {
      "pk": "234e5678-e89b-12d3-a456-426614174001",
      "username": "bob_builder",
      "email": "bob@cybermonkey.net.au",
      "type": "external",
      "is_active": true
    }
  ],
  "total_count": 2
}
```

### 6. Credential Management (`.env` files via `pkg/shared/dotenv.go`)

**Enhancement Summary** (just completed):

**New Functions**:
```go
// Write .env file with atomic rename (security-hardened)
func WriteEnvFile(filePath string, envVars map[string]string, perm os.FileMode, header string) error

// Update single variable (idempotent, preserves comments)
func UpdateEnvVar(filePath, key, value string, perm os.FileMode) error

// Load .env into process environment (for testing/scripts)
func LoadEnvVarsIntoEnvironment(filePath string) error
```

**Security Features**:
- **Atomic writes**: Temp file + rename (prevents partial writes)
- **Permissions before write**: Set 0600 BEFORE writing secrets (prevents race condition)
- **Idempotency**: `UpdateEnvVar` no-ops if value unchanged
- **Auto-quoting**: Handles spaces, special characters

**Integration with API Client**:

```yaml
# pkg/authentik/api_definition.yaml
auth:
  type: bearer_token
  token_consul_key: "service/hecate/secrets/authentik_token"  # Consul KV (preferred)
  token_env_file: "/opt/hecate/.env"                          # Fallback to .env file
  token_env_var: "AUTHENTIK_TOKEN"                            # Env var name in .env
  base_url_consul_key: "service/hecate/config/authentik_url"
```

**Credential Discovery** (fallback chain):
1. **Consul KV** (if `token_consul_key` set) → most secure, centralized
2. **Vault** (if `token_vault_path` set) → secure, rotatable
3. **.env file** (if `token_env_file` + `token_env_var` set) → local fallback
4. **Environment variable** (if `token_env_var` set) → runtime override
5. **Interactive prompt** (if TTY available) → human-centric fallback
6. **Error with remediation** (if non-interactive) → actionable guidance

**Example** (Authentik token discovery):

```go
// pkg/apiclient/auth.go
func (e *Executor) discoverAuthToken(rc *eos_io.RuntimeContext) (string, error) {
    logger := otelzap.Ctx(rc.Ctx)
    authCfg := e.definition.Auth

    // Try Consul KV first (preferred)
    if authCfg.TokenConsulKey != "" {
        token, err := consulKV.Get(authCfg.TokenConsulKey)
        if err == nil && token != "" {
            logger.Info("Using auth token from Consul KV",
                zap.String("key", authCfg.TokenConsulKey))
            return token, nil
        }
    }

    // Try Vault
    if authCfg.TokenVaultPath != "" {
        token, err := vaultClient.Read(authCfg.TokenVaultPath)
        if err == nil && token != "" {
            logger.Info("Using auth token from Vault",
                zap.String("path", authCfg.TokenVaultPath))
            return token, nil
        }
    }

    // Try .env file
    if authCfg.TokenEnvFile != "" && authCfg.TokenEnvVar != "" {
        token, found, err := shared.GetEnvVar(authCfg.TokenEnvFile, authCfg.TokenEnvVar)
        if err == nil && found && token != "" {
            logger.Info("Using auth token from .env file",
                zap.String("file", authCfg.TokenEnvFile),
                zap.String("var", authCfg.TokenEnvVar))
            return token, nil
        }
    }

    // Try environment variable
    if authCfg.TokenEnvVar != "" {
        token := os.Getenv(authCfg.TokenEnvVar)
        if token != "" {
            logger.Info("Using auth token from environment variable",
                zap.String("var", authCfg.TokenEnvVar))
            return token, nil
        }
    }

    // Interactive prompt (if TTY available)
    if interaction.IsTTY() {
        token, err := interaction.GetRequiredString(rc, "", false, &interaction.RequiredFlagConfig{
            FlagName:      "token",
            PromptMessage: fmt.Sprintf("Enter %s API token: ", e.definition.Service),
            HelpText:      "API token for authentication. Get from service admin panel.",
            IsSecret:      true,
        })
        if err != nil {
            return "", err
        }
        return token.Value, nil
    }

    // Non-interactive mode - fail with remediation
    return "", fmt.Errorf("API token not found. Set one of:\n" +
        "  - Consul KV: %s\n" +
        "  - Vault: %s\n" +
        "  - .env file: %s (%s)\n" +
        "  - Environment: %s\n" +
        "  - Or run interactively for prompt",
        authCfg.TokenConsulKey,
        authCfg.TokenVaultPath,
        authCfg.TokenEnvFile, authCfg.TokenEnvVar,
        authCfg.TokenEnvVar)
}
```

**Key Insight**: `.env` files are **local fallback**, not primary credential source. Consul/Vault are preferred for production.

---

## Extension to Other Services

### Adding Wazuh Support

**1. Create API Definition** (`pkg/wazuh/api_definition.yaml`):

```yaml
service: wazuh
version: 4.7
auth:
  type: basic
  username_env_var: WAZUH_USER
  password_env_var: WAZUH_PASSWORD
  base_url_consul_key: "service/wazuh/config/api_url"

resources:
  agents:
    path: /agents
    operations:
      list:
        method: GET
        filters:
          - name: status
            type: string
            values: [active, disconnected, never_connected]

      get:
        method: GET
        path: /agents/{agent_id}
        params:
          - name: agent_id
            type: string
            required: true
```

**2. Implement HTTP Client** (optional, if special handling needed):

```go
// pkg/wazuh/client.go
type Client struct {
    baseURL  string
    username string
    password string
    httpClient *http.Client
}

func (c *Client) DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
    // Build request with Basic Auth
    // ...
}
```

**3. Add Commands**:

```go
// cmd/list/wazuh.go
var wazuhCmd = &cobra.Command{
    Use:   "wazuh [resource]",
    Short: "List Wazuh resources",
    RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
        executor, err := apiclient.NewExecutor(rc, "wazuh")
        // ... same pattern as Authentik
    }),
}
```

**No framework code changes required** - just configuration!

### Adding Caddy Support

**API Definition** (`pkg/caddy/api_definition.yaml`):

```yaml
service: caddy
version: 2.8
base_url: "http://localhost:2019"  # Admin API
auth:
  type: none  # Admin API unauthenticated on localhost

resources:
  config:
    path: /config
    operations:
      get:
        method: GET
        description: "Get current Caddy configuration"

      update:
        method: POST
        path: /load
        description: "Load new Caddy configuration"
        fields:
          - name: config
            type: json
            required: true
```

**Usage**:

```bash
# Get Caddy config
eos read caddy config

# Update Caddy config (with interactive JSON editor)
eos update caddy config
```

---

## Interactive Mode Examples

### Missing Required Field

**Command**:
```bash
$ eos create authentik user
```

**Behavior** (CLAUDE.md P0 #13 - Human-Centric):
```
Username is required for user creation.
How to provide: Use --username flag or enter below

Enter username: alice
✓ Username: alice

Email is required for user creation.
How to provide: Use --email flag or enter below

Enter email: alice@example.com
✓ Email: alice@example.com

User type (optional)
Options: internal, external, service_account
Default: internal
Press Enter for default or type value: [Enter]
✓ User type: internal (default)

Creating user...
✓ Created user alice (UUID: 123e4567-e89b-12d3-a456-426614174000)
```

### Invalid Input Validation

**Command**:
```bash
$ eos create authentik user --username=alice --email=invalid
```

**Behavior**:
```
✗ Validation failed: email is not a valid email address

Email is required and must be valid.
Format: user@example.com

Enter email: alice@
✗ Still invalid. Format: user@example.com

Enter email: alice@example.com
✓ Email: alice@example.com

Creating user...
✓ Created user alice (UUID: 123e4567-e89b-12d3-a456-426614174000)
```

### Destructive Operation Confirmation

**Command**:
```bash
$ eos delete authentik user 123e4567-e89b-12d3-a456-426614174000
```

**Behavior**:
```
⚠️  This will permanently delete user 123e4567-e89b-12d3-a456-426614174000. Continue?

Type 'yes' to confirm: yes
Deleting user...
✓ User deleted successfully
```

**Without `--force` (prevented)**:
```bash
$ eos delete authentik user 123e4567-e89b-12d3-a456-426614174000
✗ Error: Destructive operation requires --force flag

To delete this user:
  eos delete authentik user 123e4567-e89b-12d3-a456-426614174000 --force
```

---

## Testing Strategy

### 1. Unit Tests

**YAML Parsing** (`pkg/apiclient/definition_test.go`):
```go
func TestLoadAPIDefinition(t *testing.T) {
    def, err := apiclient.LoadDefinition("authentik")
    require.NoError(t, err)
    assert.Equal(t, "authentik", def.Service)
    assert.Equal(t, "2025.10", def.Version)
    assert.Contains(t, def.Resources, "users")
}
```

**Type Validation** (`pkg/apiclient/validation_test.go`):
```go
func TestValidateUUID(t *testing.T) {
    tests := []struct {
        input string
        valid bool
    }{
        {"123e4567-e89b-12d3-a456-426614174000", true},
        {"not-a-uuid", false},
        {"", false},
    }

    for _, tt := range tests {
        err := apiclient.ValidateParameter(tt.input, apiclient.ParameterTypeUUID)
        if tt.valid {
            assert.NoError(t, err)
        } else {
            assert.Error(t, err)
        }
    }
}
```

**Dotenv Enhancements** (`pkg/shared/dotenv_test.go`):
```go
func TestWriteEnvFile(t *testing.T) {
    tmpDir := t.TempDir()
    envFile := filepath.Join(tmpDir, ".env")

    envVars := map[string]string{
        "AUTHENTIK_TOKEN": "test_token_123",
        "AUTHENTIK_URL":   "https://auth.example.com",
    }

    err := shared.WriteEnvFile(envFile, envVars, 0600, "# Test Config")
    require.NoError(t, err)

    // Verify permissions
    info, err := os.Stat(envFile)
    require.NoError(t, err)
    assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

    // Verify content
    parsed, err := shared.ParseEnvFile(envFile)
    require.NoError(t, err)
    assert.Equal(t, "test_token_123", parsed["AUTHENTIK_TOKEN"])
}

func TestUpdateEnvVarIdempotency(t *testing.T) {
    tmpDir := t.TempDir()
    envFile := filepath.Join(tmpDir, ".env")

    // Write initial value
    err := shared.UpdateEnvVar(envFile, "KEY", "value1", 0600)
    require.NoError(t, err)

    // Get file modification time
    info1, _ := os.Stat(envFile)
    time.Sleep(10 * time.Millisecond)

    // Update with same value (should be no-op)
    err = shared.UpdateEnvVar(envFile, "KEY", "value1", 0600)
    require.NoError(t, err)

    // File should NOT have been modified
    info2, _ := os.Stat(envFile)
    assert.Equal(t, info1.ModTime(), info2.ModTime(), "File should not be rewritten if value unchanged")
}
```

### 2. Integration Tests

**Mocked API Responses** (`pkg/apiclient/executor_test.go`):
```go
type mockHTTPClient struct {
    responses map[string][]byte
}

func (m *mockHTTPClient) DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
    key := fmt.Sprintf("%s %s", method, path)
    if resp, ok := m.responses[key]; ok {
        return resp, nil
    }
    return nil, fmt.Errorf("unexpected request: %s", key)
}

func TestExecutorList(t *testing.T) {
    mockClient := &mockHTTPClient{
        responses: map[string][]byte{
            "GET /api/v3/core/users": []byte(`{
                "results": [
                    {"pk": "123", "username": "alice", "email": "alice@example.com"}
                ],
                "pagination": {"count": 1}
            }`),
        },
    }

    executor := &apiclient.Executor{
        definition: loadTestDefinition("authentik"),
        httpClient: mockClient,
    }

    result, err := executor.List(context.Background(), "users", nil)
    require.NoError(t, err)
    assert.Len(t, result.Items, 1)
    assert.Equal(t, "alice", result.Items[0]["username"])
}
```

### 3. End-to-End Tests (Optional, CI-Gated)

**Live Authentik Instance** (`pkg/apiclient/e2e_test.go`):
```go
// +build e2e

func TestE2EAuthentikUserCRUD(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping E2E test in short mode")
    }

    rc := setupTestRuntimeContext(t)
    executor, err := apiclient.NewExecutor(rc, "authentik")
    require.NoError(t, err)

    // Create user
    createResult, err := executor.Create(context.Background(), "users", map[string]interface{}{
        "username": "test_user_" + randomString(8),
        "email":    "test@example.com",
        "type":     "internal",
    })
    require.NoError(t, err)
    userPK := createResult.ID.(string)
    defer executor.Delete(context.Background(), "users", map[string]interface{}{"pk": userPK})

    // Read user
    getResult, err := executor.Get(context.Background(), "users", map[string]interface{}{"pk": userPK})
    require.NoError(t, err)
    assert.Equal(t, "test@example.com", getResult.Item["email"])

    // Update user
    updateResult, err := executor.Update(context.Background(), "users",
        map[string]interface{}{"pk": userPK},
        map[string]interface{}{"is_active": false},
    )
    require.NoError(t, err)
    assert.False(t, updateResult.Item["is_active"].(bool))

    // Delete user
    deleteResult, err := executor.Delete(context.Background(), "users", map[string]interface{}{"pk": userPK})
    require.NoError(t, err)
    assert.True(t, deleteResult.Success)
}
```

**Run E2E tests**:
```bash
# Skip E2E tests (default)
go test ./pkg/apiclient/...

# Run E2E tests (requires live Authentik instance)
AUTHENTIK_URL=https://auth.example.com \
AUTHENTIK_TOKEN=ak_test_token \
go test -tags=e2e ./pkg/apiclient/...
```

---

## Migration Path

### Phase 1: Framework Foundation (Current)
- ✅ Design architecture (this document)
- ✅ Enhance `pkg/shared/dotenv.go` with write capabilities
- ✅ Define API definition schema (`pkg/apiclient/types.go`)
- ⏳ Implement executor, YAML loader, output formatter
- ⏳ Create Authentik API definition
- ⏳ Implement `eos list authentik`, `eos read authentik`

### Phase 2: Full CRUD Coverage (Week of 2025-11-10)
- Add `eos create authentik`, `eos update authentik`, `eos delete authentik`
- Interactive prompting for missing fields
- Validation and error handling with remediation
- Confirmation prompts for destructive operations

### Phase 3: Advanced Features (Week of 2025-11-17)
- Subresource support (user permissions, flow bindings)
- Batch operations (update multiple resources)
- Dry-run mode (`--dry-run` flag)
- Rate limiting and retry logic

### Phase 4: Additional Services (2025-12 → 2026-01)
- Wazuh API definition (`pkg/wazuh/api_definition.yaml`)
- Caddy API definition (`pkg/caddy/api_definition.yaml`)
- Generic OpenAPI schema importer (auto-generate YAML from OpenAPI spec)

---

## Files Created/Modified

### New Files
1. **`pkg/apiclient/README.md`** - Framework documentation
2. **`pkg/apiclient/types.go`** - Type definitions (APIDefinition, Operation, etc.)
3. **`docs/API_CLIENT_FRAMEWORK_DESIGN.md`** - This document (design summary)

### Enhanced Files
1. **`pkg/shared/dotenv.go`** - Added `WriteEnvFile()`, `UpdateEnvVar()`, `LoadEnvVarsIntoEnvironment()`

### Pending Files (Next Steps)
1. **`pkg/apiclient/definition.go`** - YAML loader
2. **`pkg/apiclient/executor.go`** - Runtime operation executor
3. **`pkg/apiclient/validation.go`** - Type validation (UUID, email, etc.)
4. **`pkg/apiclient/output.go`** - Output formatting (table, JSON, YAML, CSV)
5. **`pkg/apiclient/auth.go`** - Credential discovery (Consul/Vault/.env fallback)
6. **`pkg/authentik/api_definition.yaml`** - Authentik resource definitions
7. **`cmd/list/authentik.go`** - List command
8. **`cmd/read/authentik.go`** - Read command
9. **`cmd/update/authentik.go`** - Update command (PATCH)
10. **`cmd/create/authentik.go`** - Create command (POST)
11. **`cmd/delete/authentik.go`** - Delete command

---

## Next Steps

### Immediate (This Session)
1. ✅ Design framework architecture
2. ✅ Enhance dotenv package
3. ✅ Create design summary document
4. ⏳ Implement YAML loader and executor
5. ⏳ Create Authentik API definition
6. ⏳ Build first command (`eos list authentik users`)
7. ⏳ Test and verify with `go build`, `golangci-lint`, `go test`

### Follow-Up (Next Session)
1. Implement remaining commands (read, create, update, delete)
2. Add interactive prompting
3. Implement output formatting
4. Write comprehensive tests
5. Document usage patterns in CLAUDE.md
6. Update ROADMAP.md with framework milestones

---

## Questions & Answers

### Q: Why runtime interpretation instead of code generation?

**A**: Faster iteration, smaller codebase, hot-reloadable definitions. Tradeoff is slight startup delay (parse YAML) vs. compile-time safety.

### Q: How does this comply with CLAUDE.md P0 rules?

**A**:
- Uses `RuntimeContext` (all operations)
- Structured logging via `otelzap.Ctx(rc.Ctx)`
- Secrets from Consul/Vault (never hardcoded)
- Interactive prompting via `pkg/interaction/required_flag.go`
- Business logic in `pkg/`, orchestration in `cmd/`

### Q: How does this integrate with existing Authentik client?

**A**: Uses `pkg/authentik/unified_client.go` as HTTP transport (adapter pattern). No changes to unified client needed - it already implements the `HTTPClient` interface.

### Q: Can this replace Wazuh API calls in the future?

**A**: Yes! Create `pkg/wazuh/api_definition.yaml`, implement `wazuh.Client` (if needed), add commands. Framework handles the rest.

### Q: What about pagination?

**A**: API definition can specify pagination params. Executor handles `next_page` URLs. Commands can add `--limit` and `--page` flags.

### Q: What about authentication methods beyond bearer tokens?

**A**: `AuthConfig` supports `basic`, `api_key`, `none`. Extend `HTTPClient` interface for OAuth, SAML, etc.

---

## References

- **CLAUDE.md**: P0 rules, human-centric philosophy, architecture patterns
- **ROADMAP.md**: Authentik 2025.10 compliance, client consolidation timeline
- **pkg/authentik/unified_client.go**: HTTP transport layer (adapter)
- **pkg/interaction/required_flag.go**: Interactive prompting pattern (P0 #13)
- **pkg/shared/dotenv.go**: Credential storage and retrieval

---

**End of Design Summary**
