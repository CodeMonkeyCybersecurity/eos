# API Client Framework - Implementation Status & Next Steps

*Last Updated: 2025-11-03*

**Purpose**: Generic, declarative framework for mapping OpenAPI/REST APIs to human-friendly CLI commands.

**Status**: 80% Complete - Core infrastructure + list commands working, CRUD commands pending

## 🎉 **READY TO USE** - List Authentik Resources Now!

```bash
# Build Eos
go build -o eos ./cmd/

# List Authentik users
sudo eos list authentik-api users

# Filter users
sudo eos list authentik-api users --type=external --superuser

# Output as JSON
sudo eos list authentik-api users --format=json
```

**See [USAGE.md](USAGE.md) for complete usage guide.**

---

## 📊 Implementation Status

### ✅ Completed (80%)

| Component | File | Status | Lines | Notes |
|-----------|------|--------|-------|-------|
| Type System | `types.go` | ✅ Complete | 240 | All data structures defined |
| YAML Loader | `definition.go` | ✅ Complete | 296 | Caching, validation, search paths |
| Auth Discovery | `auth.go` | ✅ Complete | 258 | .env priority (authoritative) |
| Validation | `validation.go` | ✅ Complete | 399 | UUID, email, boolean, enum, JSON |
| **Runtime Executor** | `executor.go` | ✅ Complete | 655 | CRUD operations (List, Get, Create, Update, Delete) |
| **Output Formatter** | `output.go` | ✅ Complete | 350 | Table, JSON, YAML, CSV formats |
| **Authentik API Definition** | `../authentik/api_definition.yaml` | ✅ Complete | 390 | Users, groups, flows, applications, providers, brands |
| **List Command** | `../../cmd/list/authentik_api.go` | ✅ Complete | 185 | Working command with all filters |
| Dotenv Enhancement | `../shared/dotenv.go` | ✅ Complete | 291 | WriteEnvFile, UpdateEnvVar added |
| Design Docs | `README.md`, `USAGE.md`, `docs/API_CLIENT_FRAMEWORK_DESIGN.md` | ✅ Complete | ~7000 | Comprehensive documentation |

**Total Lines Written**: ~3,064 lines of production code (ready to use!)

### ⏳ Remaining Work (20%)

| Component | File | Priority | Estimated Lines | Complexity |
|-----------|------|----------|-----------------|------------|
| **Read Command** | `../../cmd/read/authentik_api.go` | P1 | 100-150 | Low - get single resource by ID |
| **Create Command** | `../../cmd/create/authentik_api.go` | P2 | 150-200 | Medium - interactive prompts |
| **Update Command** | `../../cmd/update/authentik_api.go` | P2 | 150-200 | Medium - interactive prompts |
| **Delete Command** | `../../cmd/delete/authentik_api.go` | P2 | 100-150 | Low - confirmation prompts |
| **Unit Tests** | `*_test.go` | P1 | 500-600 | Medium - comprehensive coverage |

**Estimated Remaining**: ~1,000-1,300 lines

---

## 🎯 Next Session: Detailed Implementation Plan

### Phase 1: Runtime Executor (P0 - CRITICAL)

**File**: `pkg/apiclient/executor.go`

**Purpose**: Core business logic that executes API operations (list, get, create, update, delete)

**Key Structures**:
```go
type Executor struct {
    definition *APIDefinition       // Loaded from YAML
    httpClient HTTPClient            // Service-specific transport (e.g., authentik.UnifiedClient)
    rc         *eos_io.RuntimeContext // For logging, tracing, secrets
}
```

**Required Functions**:

1. **NewExecutor(rc, service) → (*Executor, error)**
   - Load API definition via `LoadDefinition(service)`
   - Discover auth token via `DiscoverAuthToken(rc, def.Auth, service)`
   - Discover base URL via `DiscoverBaseURL(rc, def.Auth, def.BaseURL, service)`
   - Create HTTPClient (for Authentik: `authentik.NewUnifiedClient(baseURL, token)`)
   - Return initialized Executor

2. **List(ctx, resource, filters) → (*ListResult, error)**
   - Get operation definition: `GetOperation(def, resource, "list")`
   - Validate filters: `ValidateParameters(filters, operation.Filters)`
   - Build query string from filters
   - Build HTTP path: `operation.Path` or `resource.Path`
   - Call `httpClient.DoRequest(ctx, "GET", path+"?"+queryString, nil)`
   - Parse JSON response
   - Extract pagination info (total_count, next_page)
   - Return `ListResult{Items: [...], TotalCount: X}`

3. **Get(ctx, resource, params) → (*GetResult, error)**
   - Get operation definition: `GetOperation(def, resource, "get")`
   - Validate params: `ValidateParameters(params, operation.Params)`
   - Build path with substitutions: `/api/v3/core/users/{pk}` → `/api/v3/core/users/123-uuid`
   - Call `httpClient.DoRequest(ctx, "GET", path, nil)`
   - Parse JSON response
   - Return `GetResult{Item: {...}}`

4. **Create(ctx, resource, fields) → (*CreateResult, error)**
   - Get operation definition: `GetOperation(def, resource, "create")`
   - Validate fields: `ValidateFields(fields, operation.Fields)`
   - Convert to typed values: `ConvertToTypedValue()` for each field
   - Call `httpClient.DoRequest(ctx, "POST", path, fields)`
   - Parse JSON response
   - Extract created ID (pk, id, uuid field)
   - Return `CreateResult{ID: X, Item: {...}}`

5. **Update(ctx, resource, params, fields) → (*UpdateResult, error)**
   - Get operation definition: `GetOperation(def, resource, "update")`
   - Validate params: `ValidateParameters(params, operation.Params)`
   - Validate fields: `ValidateFields(fields, operation.Fields)`
   - Build path with param substitutions
   - Call `httpClient.DoRequest(ctx, "PATCH", path, fields)` (or PUT if operation.Method == PUT)
   - Parse JSON response
   - Return `UpdateResult{Item: {...}}`

6. **Delete(ctx, resource, params) → (*DeleteResult, error)**
   - Get operation definition: `GetOperation(def, resource, "delete")`
   - Validate params: `ValidateParameters(params, operation.Params)`
   - Check if confirmation required: `operation.Confirm`
   - Build path with param substitutions
   - Call `httpClient.DoRequest(ctx, "DELETE", path, nil)`
   - Return `DeleteResult{Success: true}`

**Helper Functions**:
- `buildPath(template, params) → string` - Replace `{pk}` with actual values
- `buildQueryString(filters) → string` - Convert map to `?key1=val1&key2=val2`
- `parseListResponse(body) → (*ListResult, error)` - Handle Authentik pagination format
- `parseItemResponse(body) → (map[string]interface{}, error)` - Parse single item

**Error Handling**:
- Wrap all errors with context: `fmt.Errorf("failed to list users: %w", err)`
- Include API response body in errors for debugging
- Log operations with structured logging: `logger.Info("Executing API operation", zap.String("method", "GET"), zap.String("path", path))`

**Integration with Authentik UnifiedClient**:
```go
// Authentik's UnifiedClient already implements HTTPClient interface
// Just need to cast it properly
client := authentik.NewUnifiedClient(baseURL, token)
executor := &Executor{
    definition: def,
    httpClient: client, // UnifiedClient.DoRequest(ctx, method, path, body) already exists
    rc:         rc,
}
```

---

### Phase 2: Output Formatter (P0 - CRITICAL)

**File**: `pkg/apiclient/output.go`

**Purpose**: Format API responses for human-readable display (default: table format)

**Required Functions**:

1. **FormatOutput(rc, data, format) → error**
   - Switch on format: "table", "json", "yaml", "csv"
   - Call appropriate formatter
   - Write to stdout (structured logging already captured diagnostics)

2. **formatTable(rc, data) → error**
   - For ListResult: render as aligned columns
   - For GetResult: render as key-value pairs
   - Use `text/tabwriter` for alignment
   - Truncate long values with "..." (max 50 chars per cell)
   - Example output:
     ```
     PK                                    USERNAME         EMAIL                    TYPE      ACTIVE
     123e4567-e89b-12d3-a456-426614174000  alice_wonderland alice@example.com       external  true
     234e5678-e89b-12d3-a456-426614174001  bob_builder      bob@example.com         external  true
     ```

3. **formatJSON(rc, data) → error**
   - Marshal to JSON with indentation
   - Write to stdout

4. **formatYAML(rc, data) → error**
   - Marshal to YAML
   - Write to stdout

5. **formatCSV(rc, data) → error**
   - For ListResult: write CSV with headers
   - Use `encoding/csv` package

**Table Rendering Details**:
- Detect terminal width (fallback: 120 columns)
- Column widths: auto-calculate based on longest value
- Truncation: long UUIDs show first 8 chars + "..."
- Colors (optional): use `github.com/fatih/color` for headers (blue), warnings (yellow)

---

### Phase 3: Authentik API Definition (P0 - CRITICAL)

**File**: `pkg/authentik/api_definition.yaml`

**Purpose**: Declarative definition of Authentik API resources

**Complete YAML Structure**:

```yaml
service: authentik
version: 2025.10

# Authentication configuration (AUTHORITATIVE PRIORITY)
auth:
  type: bearer_token

  # Priority 1: .env file (PRIMARY for next 6 months)
  token_env_file: "/opt/hecate/.env"
  token_env_var: "AUTHENTIK_TOKEN"

  # Priority 2: Consul KV (preferred long-term)
  token_consul_key: "service/hecate/secrets/authentik_token"

  # Priority 3: Vault (secure, rotatable)
  token_vault_path: "secret/hecate/authentik_token"

  # Base URL discovery
  base_url_env_file: "/opt/hecate/.env"
  base_url_env_var: "AUTHENTIK_URL"
  base_url_consul_key: "service/hecate/config/authentik_url"

# Resource definitions
resources:
  # Users resource (from your draft API calls)
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
        output_fields: [pk, username, email, type, groups, groups_obj]

      create:
        method: POST
        description: "Create a new user"
        fields:
          - name: username
            type: string
            required: true
            description: "Unique username"
            help_text: "Username for login (lowercase, no spaces)"
          - name: email
            type: email
            required: true
            description: "User email address"
            help_text: "Valid email address (e.g., user@example.com)"
          - name: type
            type: enum
            values: [internal, external, service_account]
            default: internal
            description: "User type"
            help_text: "internal = managed by Authentik, external = federated SSO"
        returns: "User UUID"

      update:
        method: PATCH
        path: /api/v3/core/users/{pk}
        description: "Update user attributes"
        params:
          - name: pk
            type: uuid
            required: true
            description: "User UUID to update"
        fields:
          - name: type
            type: enum
            values: [internal, external, service_account]
            description: "Change user type"
          - name: is_active
            type: boolean
            description: "Enable or disable user account"

      delete:
        method: DELETE
        path: /api/v3/core/users/{pk}
        description: "Delete a user permanently"
        params:
          - name: pk
            type: uuid
            required: true
            description: "User UUID to delete"
        confirm: true
        confirm_message: "This will permanently delete user {pk}. Continue?"

    # Nested resources (from your draft: GET /api/v3/core/users/{pk}/permissions/)
    subresources:
      permissions:
        path: /api/v3/core/users/{pk}/permissions
        description: "User's effective permissions"
        operations:
          list:
            method: GET
            description: "List all permissions for user"

      roles:
        path: /api/v3/core/users/{pk}/roles
        description: "User's assigned roles"
        operations:
          list:
            method: GET
            description: "List all roles for user"

  # Groups resource (from your draft API calls)
  groups:
    path: /api/v3/core/groups
    description: "Manage Authentik groups"

    operations:
      list:
        method: GET
        description: "List all groups"
        filters:
          - name: members_by_pk
            type: uuid
            description: "Filter groups by member UUID"
        output_fields: [pk, name, num_members]

      get:
        method: GET
        path: /api/v3/core/groups/{pk}
        description: "Get group details"
        params:
          - name: pk
            type: uuid
            required: true
            description: "Group UUID"
        output_fields: [pk, name, users, users_obj, attributes]

  # Flows resource (from your draft: GET /api/v3/flows/instances/)
  flows:
    path: /api/v3/flows/instances
    description: "Manage Authentik flows"

    operations:
      list:
        method: GET
        description: "List all flows"
        filters:
          - name: designation
            type: enum
            values: [authentication, authorization, enrollment, invalidation, recovery, unenrollment]
            description: "Filter by flow designation"
        output_fields: [pk, slug, name, designation]

      get:
        method: GET
        path: /api/v3/flows/instances/{pk}
        description: "Get flow details"
        params:
          - name: pk
            type: uuid
            required: true
            description: "Flow UUID"
        output_fields: [pk, slug, name, designation, stages]

    # Nested resource (from your draft: GET /api/v3/flows/bindings/?target={flow})
    subresources:
      bindings:
        path: /api/v3/flows/bindings
        description: "Flow stage bindings"
        operations:
          list:
            method: GET
            description: "List stage bindings for flow"
            filters:
              - name: target
                type: uuid
                description: "Flow UUID to get bindings for"
              - name: order
                type: string
                description: "Sort order (e.g., 'order')"
```

**Validation Checklist**:
- [ ] All resources from your draft API calls included (users, groups, flows)
- [ ] All operations match your examples (GET, PATCH, POST, DELETE)
- [ ] All filters match your usage patterns (is_superuser, type, members_by_pk, designation)
- [ ] Nested resources work (permissions, roles, bindings)
- [ ] Auth config uses .env priority (authoritative)

---

### Phase 4: List Command (P1 - HIGH PRIORITY)

**File**: `cmd/list/authentik.go`

**Purpose**: User-facing command for listing Authentik resources

**Complete Implementation**:

```go
// cmd/list/authentik.go
package list

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/apiclient"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var authentikCmd = &cobra.Command{
	Use:   "authentik [resource]",
	Short: "List Authentik resources",
	Long: `List Authentik resources with optional filters.

Available resources:
  users      - List Authentik users
  groups     - List Authentik groups
  flows      - List Authentik flows

Examples:
  # List all users
  eos list authentik users

  # List external users only
  eos list authentik users --type=external

  # List superusers
  eos list authentik users --superuser=true

  # List groups containing specific user
  eos list authentik groups --member=123e4567-e89b-12d3-a456-426614174000

  # List enrollment flows
  eos list authentik flows --designation=enrollment

  # Output as JSON
  eos list authentik users --format=json`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Require resource argument
		if len(args) < 1 {
			return fmt.Errorf("resource type required\n\n" +
				"Available resources: users, groups, flows\n" +
				"Example: eos list authentik users")
		}

		resource := args[0]

		// Create executor (loads API definition, discovers auth)
		executor, err := apiclient.NewExecutor(rc, "authentik")
		if err != nil {
			return fmt.Errorf("failed to initialize Authentik API client: %w\n\n"+
				"Troubleshooting:\n"+
				"  1. Ensure Authentik is configured in /opt/hecate/.env\n"+
				"  2. Check AUTHENTIK_TOKEN and AUTHENTIK_URL are set\n"+
				"  3. Run: eos debug hecate", err)
		}

		// Extract filters from flags
		filters := make(map[string]interface{})

		// Users filters
		if resource == "users" {
			if cmd.Flags().Changed("superuser") {
				superuser, _ := cmd.Flags().GetBool("superuser")
				filters["is_superuser"] = superuser
			}
			if cmd.Flags().Changed("type") {
				userType, _ := cmd.Flags().GetString("type")
				filters["type"] = userType
			}
		}

		// Groups filters
		if resource == "groups" {
			if cmd.Flags().Changed("member") {
				member, _ := cmd.Flags().GetString("member")
				filters["members_by_pk"] = member
			}
		}

		// Flows filters
		if resource == "flows" {
			if cmd.Flags().Changed("designation") {
				designation, _ := cmd.Flags().GetString("designation")
				filters["designation"] = designation
			}
		}

		logger.Info("Listing Authentik resources",
			zap.String("resource", resource),
			zap.Any("filters", filters))

		// Execute list operation
		result, err := executor.List(rc.Ctx, resource, filters)
		if err != nil {
			return fmt.Errorf("failed to list %s: %w", resource, err)
		}

		logger.Info("Retrieved resources",
			zap.Int("count", len(result.Items)),
			zap.Int("total", result.TotalCount))

		// Format and display output
		format, _ := cmd.Flags().GetString("format")
		if err := apiclient.FormatOutput(rc, result, format); err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}

		return nil
	}),
}

func init() {
	// Standard flags (all resources)
	authentikCmd.Flags().String("format", "table", "Output format (table, json, yaml, csv)")

	// Users filters
	authentikCmd.Flags().Bool("superuser", false, "Filter by superuser status")
	authentikCmd.Flags().String("type", "", "Filter by user type (internal, external, service_account)")

	// Groups filters
	authentikCmd.Flags().String("member", "", "Filter groups by member UUID")

	// Flows filters
	authentikCmd.Flags().String("designation", "", "Filter flows by designation (authentication, enrollment, etc.)")

	// Register command
	listCmd.AddCommand(authentikCmd)
}
```

**Testing Checklist**:
- [ ] `eos list authentik users` works
- [ ] `eos list authentik users --type=external` filters correctly
- [ ] `eos list authentik groups --member={uuid}` works
- [ ] `eos list authentik flows --designation=enrollment` works
- [ ] `--format=json` outputs valid JSON
- [ ] `--format=table` renders human-readable table
- [ ] Error messages include remediation steps

---

### Phase 5: Additional Commands (P1-P2)

**Similar pattern to list command, lower complexity**:

1. **Read Command** (`cmd/read/authentik.go`) - ~100 lines
   - Takes resource + UUID argument
   - Calls `executor.Get(ctx, resource, {"pk": uuid})`
   - Displays single item

2. **Create Command** (`cmd/create/authentik.go`) - ~150 lines
   - Interactive prompts for required fields
   - Calls `executor.Create(ctx, resource, fields)`
   - Displays created item UUID

3. **Update Command** (`cmd/update/authentik.go`) - ~150 lines
   - Takes resource + UUID + field flags
   - Calls `executor.Update(ctx, resource, params, fields)`
   - Displays updated item

4. **Delete Command** (`cmd/delete/authentik.go`) - ~100 lines
   - Requires `--force` flag (safety)
   - Calls `executor.Delete(ctx, resource, {"pk": uuid})`
   - Confirms deletion

---

### Phase 6: Tests (P1 - CRITICAL)

**Test Files to Create**:

1. **`pkg/apiclient/definition_test.go`** - YAML loading, validation
2. **`pkg/apiclient/auth_test.go`** - Credential discovery priority order
3. **`pkg/apiclient/validation_test.go`** - Type validation (UUID, email, etc.)
4. **`pkg/apiclient/executor_test.go`** - Mocked HTTP responses
5. **`pkg/shared/dotenv_test.go`** - Enhanced with WriteEnvFile, UpdateEnvVar tests

**Testing Strategy**:
- Unit tests with mocked HTTP client
- Table-driven tests for validation
- Idempotency tests for dotenv functions
- Error message validation (ensure remediation steps present)

---

## 🚀 Immediate Next Steps (Start Here)

### Step 1: Build executor.go (400-500 lines)
```bash
# Create file
touch pkg/apiclient/executor.go

# Start with struct and NewExecutor()
# Then implement List(), Get(), Create(), Update(), Delete()
# Add helper functions (buildPath, buildQueryString, etc.)
```

### Step 2: Build output.go (300-400 lines)
```bash
# Create file
touch pkg/apiclient/output.go

# Implement FormatOutput() switch
# Implement formatTable() (most complex - use tabwriter)
# Implement formatJSON(), formatYAML(), formatCSV()
```

### Step 3: Write Authentik API definition (200-300 lines YAML)
```bash
# Create file
touch pkg/authentik/api_definition.yaml

# Copy structure from Phase 3 above
# Validate against your draft API calls
```

### Step 4: Build list command (100-150 lines)
```bash
# Create file
touch cmd/list/authentik.go

# Copy implementation from Phase 4 above
# Wire into cmd/list/list.go
```

### Step 5: Test and verify
```bash
# Build
go build -o /tmp/eos-build ./cmd/

# Run
/tmp/eos-build list authentik users --format=table

# Expected: Table of Authentik users
```

---

## 📝 Design Philosophy

### 1. Human-Centric (CLAUDE.md P0)
- **Interactive fallback**: Missing parameters prompt the user (informed consent)
- **Plain language**: REST verbs map to intuitive CLI commands (`GET` → `list`/`read`)
- **Helpful errors**: Validation failures include remediation steps

### 2. Declarative Configuration
- **API definitions in YAML**: Service-specific files define resources, operations, parameters
- **Runtime interpretation**: No code generation - YAML drives behavior dynamically
- **Hot-reloadable**: Update API definitions without recompiling Eos

### 3. Compliance with Existing Patterns
- **Authentik 2025.10**: Uses `pkg/authentik/unified_client.go` as HTTP transport
- **RuntimeContext**: All operations accept `*eos_io.RuntimeContext`
- **Structured logging**: Uses `otelzap.Ctx(rc.Ctx)` for telemetry
- **Secret management**: Credentials via Consul/Vault (not hardcoded)

### 4. Generic and Extensible
- **Service-agnostic**: Framework works for Authentik, Wazuh, Caddy, any OpenAPI service
- **Minimal boilerplate**: Add new API with ~100 lines of YAML (no Go code)
- **Composable**: Nest resources, chain operations, share types

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

---

## Resource Hierarchy

APIs have nested resources. Framework maps them to Eos's noun structure:

```
eos [verb] [service] [resource] [subresource] [id] [--flags]
```

**Examples**:
```bash
# Flat resources
GET /api/v3/core/users/           → eos list authentik users
GET /api/v3/core/users/{pk}/      → eos read authentik user {pk}

# Nested resources (user's permissions)
GET /api/v3/core/users/{pk}/permissions/  → eos read authentik user {pk} permissions
GET /api/v3/core/users/{pk}/roles/        → eos list authentik user {pk} roles
```

---

## API Definition File Structure

**Location**: `pkg/[service]/api_definition.yaml`

**Schema**:
```yaml
service: authentik
version: 2025.10  # API version we're targeting
base_url_consul_key: "service/hecate/config/authentik_url"
auth:
  type: bearer_token
  token_consul_key: "service/hecate/secrets/authentik_token"
  # Alternative: token_vault_path: "secret/hecate/authentik_token"

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
        output_fields: [pk, username, email, type, groups, groups_obj]

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
            description: "User type"
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

      roles:
        path: /api/v3/core/users/{pk}/roles
        description: "User's assigned roles"
        operations:
          list:
            method: GET
            description: "List user roles"

  groups:
    path: /api/v3/core/groups
    description: "Manage Authentik groups"
    operations:
      list:
        method: GET
        filters:
          - name: members_by_pk
            type: uuid
            description: "Filter groups by member UUID"

      get:
        method: GET
        path: /api/v3/core/groups/{pk}
        params:
          - name: pk
            type: uuid
            required: true
```

---

## Implementation Architecture

### 1. Runtime Executor (`pkg/apiclient/executor.go`)

**Responsibilities**:
- Load and parse API definition YAML
- Validate operation exists for resource
- Build HTTP request from operation definition
- Delegate HTTP transport to service-specific client (e.g., `pkg/authentik/unified_client.go`)
- Parse and format response

**Key methods**:
```go
type Executor struct {
    definition *APIDefinition
    httpClient HTTPClient  // Interface - can be Authentik, Wazuh, Caddy client
}

func (e *Executor) List(ctx context.Context, resource string, filters map[string]interface{}) (interface{}, error)
func (e *Executor) Get(ctx context.Context, resource string, params map[string]interface{}) (interface{}, error)
func (e *Executor) Create(ctx context.Context, resource string, fields map[string]interface{}) (interface{}, error)
func (e *Executor) Update(ctx context.Context, resource string, params map[string]interface{}, fields map[string]interface{}) (interface{}, error)
func (e *Executor) Delete(ctx context.Context, resource string, params map[string]interface{}) error
```

### 2. Command Generator (`cmd/list/authentik.go`, `cmd/read/authentik.go`, etc.)

**Pattern**:
- Load API definition for service
- Extract filters/params from flags
- Call executor with RuntimeContext
- Format output (table, JSON, YAML, CSV)

**Example**:
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

        // Execute operation
        results, err := executor.List(rc.Ctx, resource, filters)
        if err != nil {
            return fmt.Errorf("failed to list %s: %w", resource, err)
        }

        // Format and display output
        format, _ := cmd.Flags().GetString("format")
        return formatOutput(rc, results, format)
    }),
}
```

### 3. Output Formatting (`pkg/apiclient/output.go`)

**Formats**:
- **table**: Human-readable, aligned columns (default)
- **json**: Machine-readable, full structure
- **yaml**: Human-readable, structured
- **csv**: Spreadsheet-compatible

**Implementation**:
```go
func FormatOutput(rc *eos_io.RuntimeContext, data interface{}, format string) error {
    switch format {
    case "table":
        return formatTable(rc, data)
    case "json":
        return formatJSON(rc, data)
    case "yaml":
        return formatYAML(rc, data)
    case "csv":
        return formatCSV(rc, data)
    default:
        return fmt.Errorf("unknown format: %s (use table, json, yaml, or csv)", format)
    }
}
```

---

## Interactive Mode (Human-Centric Pattern)

### Required Fields Missing

**Scenario**: User forgets a required field
```bash
$ eos create authentik user
```

**Behavior**:
1. Check if flag was explicitly set via `cmd.Flags().Changed()`
2. Check environment variable (if configured)
3. Prompt interactively (if TTY available):
   ```
   Username is required for user creation.
   Enter username: _
   ```
4. Validate input
5. Retry on validation failure (max 3 attempts)
6. Error with remediation if non-interactive

**Implementation**: Use `pkg/interaction/required_flag.go` pattern (CLAUDE.md P0 #13)

---

## Security & Validation

### 1. Input Validation
- **Type checking**: UUID, email, boolean, string, enum
- **Range validation**: Min/max lengths, allowed values
- **Format validation**: Email regex, URL validation

### 2. Authentication
- **Credentials from Consul/Vault**: Never hardcoded (CLAUDE.md P0 #6)
- **Token rotation**: Support dynamic token refresh
- **TLS enforcement**: Minimum TLS 1.2 (already in unified_client.go)

### 3. Confirmation for Destructive Operations
- **DELETE requires --force**: Prevent accidental deletion
- **PATCH/PUT warn on replace**: Inform user of full replacement

---

## Extension to Other Services

### Adding Wazuh Support

1. **Create API definition**: `pkg/wazuh/api_definition.yaml`
2. **Implement HTTP client**: `pkg/wazuh/client.go` (or reuse if REST/JSON)
3. **Add commands**: `cmd/list/wazuh.go`, `cmd/read/wazuh.go`, etc.
4. **Register in executor**: `apiclient.NewExecutor(rc, "wazuh")`

**No changes to framework code required** - just configuration!

### Adding Caddy Support

Same pattern - define resources in `pkg/caddy/api_definition.yaml`:

```yaml
service: caddy
version: 2.8
base_url: "http://localhost:2019"  # Caddy Admin API
auth:
  type: none  # Admin API typically unauthenticated on localhost

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

---

## Testing Strategy

### 1. Unit Tests
- **YAML parsing**: Validate schema correctness
- **Type validation**: UUID, email, boolean, enum
- **Flag extraction**: Filters and params from Cobra flags

### 2. Integration Tests
- **Mocked API responses**: Test request building without live API
- **Error handling**: Validate error messages include remediation
- **Output formatting**: Verify table/JSON/YAML/CSV correctness

### 3. End-to-End Tests
- **Live Authentik instance**: Run against real API (optional, CI-gated)
- **CRUD operations**: Create, read, update, delete user
- **Nested resources**: Test subresource access

---

## Migration Path

### Phase 1: Framework Foundation (Current)
- Build executor, YAML parser, output formatter
- Create Authentik API definition
- Implement `eos list authentik`, `eos read authentik`

### Phase 2: Full CRUD Coverage
- Add `eos create authentik`, `eos update authentik`, `eos delete authentik`
- Interactive prompting for missing fields
- Validation and error handling

### Phase 3: Advanced Features
- Subresource support (user permissions, flow bindings)
- Batch operations (update multiple resources)
- Dry-run mode (`--dry-run` flag)

### Phase 4: Additional Services
- Wazuh API definition
- Caddy API definition
- Generic OpenAPI schema importer (auto-generate YAML from OpenAPI spec)

---

## Design Decisions & Rationale

### Why Runtime Interpretation (Not Code Generation)?

**Considered**:
- **Option A**: Code generation (`go run ./tools/apigen` → generates Cobra commands)
- **Option B**: Runtime interpretation (YAML drives behavior dynamically)

**Chose B** because:
1. **Faster iteration**: Update YAML without recompiling
2. **Smaller codebase**: One executor vs. generated code per resource
3. **Easier to extend**: Add new services with YAML only
4. **Hot-reloadable**: Can update API definitions in production

**Tradeoff**: Slightly slower startup (parse YAML) vs. compile-time safety

### Why YAML (Not JSON)?

- **Human-readable**: Comments, multi-line strings
- **Standard in DevOps**: Kubernetes, Ansible, Terraform use YAML
- **Less verbose**: No trailing commas, cleaner structure

### Why Unified Client Pattern?

**Follows Authentik 2025.10 architecture**:
- Consolidates HTTP clients (CLAUDE.md HTTP Client Consolidation Rule)
- Shares TLS config, timeouts, retry logic
- Single source of truth for API communication

---

## References

- **CLAUDE.md**: P0 rules, human-centric philosophy, interaction patterns
- **ROADMAP.md**: Authentik 2025.10 compliance, client consolidation timeline
- **pkg/authentik/unified_client.go**: HTTP transport layer
- **pkg/interaction/required_flag.go**: Interactive prompting pattern
