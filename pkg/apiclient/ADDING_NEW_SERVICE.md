# Adding a New Service to API Client Framework

*Last Updated: 2025-11-03*

This guide shows you how to add a new service (e.g., Wazuh, Caddy) to the API Client Framework in **3 simple steps**.

---

## Overview

To add a new service, you need:

1. **API definition YAML** (~200-300 lines) - Declarative resource definitions
2. **HTTP client implementation** (~100-200 lines) - Implements `HTTPClient` interface
3. **List command** (~100-150 lines) - Thin Cobra orchestration

**That's it!** No code generation, no boilerplate. The framework handles everything else.

---

## Step 1: Create API Definition YAML

**File**: `pkg/[service]/api_definition.yaml`

**Template**:

```yaml
service: wazuh
version: 4.7

# Authentication configuration
auth:
  type: basic  # or bearer_token, api_key, none

  # Token/credentials discovery (priority order)
  token_env_file: "/opt/wazuh/.env"
  token_env_var: "WAZUH_TOKEN"
  token_consul_key: "service/wazuh/secrets/token"
  token_vault_path: "secret/wazuh/token"

  # Base URL discovery
  base_url_env_file: "/opt/wazuh/.env"
  base_url_env_var: "WAZUH_URL"
  base_url_consul_key: "service/wazuh/config/url"

# Resource definitions
resources:
  # Example: Agents resource
  agents:
    path: /agents
    description: "Manage Wazuh agents"

    operations:
      list:
        method: GET
        description: "List all agents"
        filters:
          - name: status
            type: enum
            values: [active, disconnected, never_connected]
            description: "Filter by agent status"
          - name: os_platform
            type: string
            description: "Filter by OS platform"
        output_fields: [id, name, ip, status, os_platform]

      get:
        method: GET
        path: /agents/{id}
        description: "Get agent details"
        params:
          - name: id
            type: string
            required: true
            description: "Agent ID"
        output_fields: [id, name, ip, status, os, version, last_keep_alive]

      create:
        method: POST
        description: "Register a new agent"
        fields:
          - name: name
            type: string
            required: true
            description: "Agent name"
            help_text: "Unique name for the agent"
          - name: ip
            type: string
            required: true
            description: "Agent IP address"
            help_text: "IP address of the agent (e.g., 192.168.1.100)"
        returns: "Agent ID"

      delete:
        method: DELETE
        path: /agents/{id}
        description: "Remove an agent"
        params:
          - name: id
            type: string
            required: true
            description: "Agent ID to remove"
        confirm: true
        confirm_message: "This will permanently remove agent {id}. Continue?"
```

**Key Points:**

- Define **resources** (e.g., agents, groups, rules)
- Specify **operations** (list, get, create, update, delete)
- Define **filters** for list operations
- Define **fields** for create/update operations
- Use **output_fields** to control what's displayed

---

## Step 2: Implement HTTP Client

**File**: `pkg/[service]/client.go`

**Interface to Implement**:

```go
type HTTPClient interface {
    DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error)
}
```

**Template**:

```go
package wazuh

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

// Client represents a Wazuh API client
type Client struct {
    baseURL    string
    username   string
    password   string
    httpClient *http.Client
}

// NewClient creates a new Wazuh API client
func NewClient(baseURL, username, password string) *Client {
    tlsConfig := &tls.Config{
        MinVersion: tls.VersionTLS12,
    }

    return &Client{
        baseURL:  baseURL,
        username: username,
        password: password,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                TLSClientConfig: tlsConfig,
            },
        },
    }
}

// DoRequest performs an HTTP request (implements HTTPClient interface)
func (c *Client) DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
    // Construct full URL
    url := c.baseURL + path

    // Prepare request body
    var reqBody io.Reader
    if body != nil {
        jsonBody, err := json.Marshal(body)
        if err != nil {
            return nil, fmt.Errorf("failed to marshal request body: %w", err)
        }
        reqBody = bytes.NewReader(jsonBody)
    }

    // Create request
    req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
    if err != nil {
        return nil, fmt.Errorf("failed to create request: %w", err)
    }

    // Set authentication (basic auth example)
    req.SetBasicAuth(c.username, c.password)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")

    // Execute request
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    // Read response
    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response: %w", err)
    }

    // Check status code
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
    }

    return respBody, nil
}
```

**Key Points:**

- Implement `DoRequest()` method
- Handle authentication (Basic, Bearer, API Key, etc.)
- Configure TLS (minimum TLS 1.2)
- Set appropriate timeouts
- Return response body as `[]byte`

---

## Step 3: Register Client in Executor

**File**: `pkg/apiclient/executor.go`

**Add case to switch statement**:

```go
// Step 4: Create service-specific HTTP client
var httpClient HTTPClient
switch service {
case "authentik":
    httpClient = authentik.NewUnifiedClient(baseURL, token)
    logger.Debug("Using Authentik unified client")
case "wazuh":
    // Extract username/password from token (format: "username:password")
    parts := strings.Split(token, ":")
    if len(parts) != 2 {
        return nil, fmt.Errorf("invalid Wazuh credentials format (expected username:password)")
    }
    httpClient = wazuh.NewClient(baseURL, parts[0], parts[1])
    logger.Debug("Using Wazuh client")
default:
    return nil, fmt.Errorf("unsupported service: %s", service)
}
```

**Key Points:**

- Add case for your service
- Create appropriate client based on auth type
- Handle credentials appropriately

---

## Step 4: Create List Command

**File**: `cmd/list/[service]_api.go`

**Template**:

```go
package list

import (
    "fmt"

    "github.com/CodeMonkeyCybersecurity/eos/pkg/apiclient"
    eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
    "github.com/spf13/cobra"
    "github.com/uptrace/opentelemetry-go-extra/otelzap"
    "go.uber.org/zap"
)

var wazuhAPICmd = &cobra.Command{
    Use:   "wazuh-api [resource]",
    Short: "List Wazuh API resources",
    Long: `List Wazuh API resources with optional filters.

Available resources:
  agents  - List Wazuh agents

Examples:
  # List all agents
  eos list wazuh-api agents

  # Filter by status
  eos list wazuh-api agents --status=active

  # Output as JSON
  eos list wazuh-api agents --format=json`,
    RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
        logger := otelzap.Ctx(rc.Ctx)

        if len(args) < 1 {
            return fmt.Errorf("resource type required (agents, groups, rules, etc.)")
        }

        resource := args[0]
        logger.Info("Listing Wazuh resources", zap.String("resource", resource))

        // Create executor
        executor, err := apiclient.NewExecutor(rc, "wazuh")
        if err != nil {
            return fmt.Errorf("failed to initialize Wazuh API client: %w", err)
        }

        // Extract filters from flags
        filters := make(map[string]interface{})
        if cmd.Flags().Changed("status") {
            status, _ := cmd.Flags().GetString("status")
            filters["status"] = status
        }

        // Execute list operation
        result, err := executor.List(rc.Ctx, resource, filters)
        if err != nil {
            return fmt.Errorf("failed to list %s: %w", resource, err)
        }

        logger.Info("Retrieved resources",
            zap.Int("count", len(result.Items)),
            zap.Int("total", result.TotalCount))

        // Format output
        format, _ := cmd.Flags().GetString("format")
        return apiclient.FormatOutput(result, format)
    }),
}

func init() {
    // Standard flags
    wazuhAPICmd.Flags().String("format", "table", "Output format (table, json, yaml, csv)")

    // Resource-specific filters
    wazuhAPICmd.Flags().String("status", "", "Filter agents by status (active, disconnected, never_connected)")

    // Register command
    ListCmd.AddCommand(wazuhAPICmd)
}
```

**Key Points:**

- Thin orchestration layer
- Parse flags → call executor → format output
- Add resource-specific filter flags
- Follow existing command patterns

---

## Testing Your New Service

### 1. Verify API Definition Loads

```bash
# Build Eos
go build -o eos ./cmd/

# Try to list (will fail gracefully if credentials missing)
sudo eos list wazuh-api agents
```

### 2. Test with Mock Data

Create a simple test:

```go
// pkg/wazuh/client_test.go
package wazuh

import (
    "context"
    "testing"
)

func TestClientDoRequest(t *testing.T) {
    // Create mock server
    // Test DoRequest with various scenarios
    // Verify response handling
}
```

### 3. End-to-End Test

```bash
# Set credentials in .env
echo "WAZUH_URL=https://wazuh.example.com" >> /opt/wazuh/.env
echo "WAZUH_TOKEN=admin:password" >> /opt/wazuh/.env

# Test list command
sudo eos list wazuh-api agents

# Test filtering
sudo eos list wazuh-api agents --status=active

# Test output formats
sudo eos list wazuh-api agents --format=json
sudo eos list wazuh-api agents --format=csv
```

---

## Common Patterns

### Bearer Token Authentication

```go
// In DoRequest()
req.Header.Set("Authorization", "Bearer "+c.token)
```

### API Key Authentication

```go
// In DoRequest()
req.Header.Set("X-API-Key", c.apiKey)
```

### Query Parameter Authentication

```go
// In DoRequest()
url := c.baseURL + path + "?api_key=" + c.apiKey
```

### Pagination Handling

If your API uses pagination, adjust `parseListResponse()` in `executor.go`:

```go
// Extract next page URL (Wazuh example)
if paging, ok := response["data"].(map[string]interface{})["paging"]; ok {
    if next, ok := paging.(map[string]interface{})["next"]; ok {
        nextPage = fmt.Sprintf("%v", next)
    }
}
```

---

## Checklist

Before submitting:

- [ ] API definition YAML created (`pkg/[service]/api_definition.yaml`)
- [ ] HTTP client implements `HTTPClient` interface
- [ ] Client registered in `executor.go` switch statement
- [ ] List command created (`cmd/list/[service]_api.go`)
- [ ] Build succeeds (`go build -o eos ./cmd/`)
- [ ] List command works (`sudo eos list [service]-api [resource]`)
- [ ] Filters work (`sudo eos list [service]-api [resource] --filter=value`)
- [ ] All output formats work (table, json, yaml, csv)
- [ ] Documentation added to `pkg/[service]/README.md`

---

## Examples

See existing implementations:

- **Authentik**: `pkg/authentik/api_definition.yaml`, `pkg/authentik/unified_client.go`, `cmd/list/authentik_api.go`
- **Framework**: `pkg/apiclient/executor.go`, `pkg/apiclient/output.go`

---

## Need Help?

- **Implementation Plan**: [pkg/apiclient/README.md](README.md)
- **Usage Guide**: [pkg/apiclient/USAGE.md](USAGE.md)
- **Design Document**: [docs/API_CLIENT_FRAMEWORK_DESIGN.md](../../docs/API_CLIENT_FRAMEWORK_DESIGN.md)
- **Issue Tracker**: https://github.com/anthropics/claude-code/issues
