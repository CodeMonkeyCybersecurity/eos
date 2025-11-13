// pkg/apiclient/types.go
// Type definitions for declarative API client framework
//
// ARCHITECTURE: Declarative API definitions map OpenAPI/REST to CLI commands
// HUMAN-CENTRIC: YAML-driven configuration, no code generation required
// EXTENSIBLE: Service-agnostic framework for Authentik, Wazuh, Caddy, etc.

package apiclient

import (
	"context"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// API Definition Structure (matches YAML schema)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// APIDefinition represents a complete API service definition
// LOADED FROM: pkg/[service]/api_definition.yaml
// EXAMPLE: pkg/authentik/api_definition.yaml
type APIDefinition struct {
	Service   string              `yaml:"service"`   // Service name (e.g., "authentik", "wazuh")
	Version   string              `yaml:"version"`   // API version (e.g., "2025.10")
	BaseURL   string              `yaml:"base_url"`  // Optional direct URL (overrides discovery)
	Auth      AuthConfig          `yaml:"auth"`      // Authentication configuration
	Resources map[string]Resource `yaml:"resources"` // Resource definitions (users, groups, etc.)
}

// AuthConfig defines how to authenticate with the API
type AuthConfig struct {
	Type AuthType `yaml:"type"` // Authentication type (bearer_token, basic, none)

	// Token discovery (priority: env_file → consul → vault → env_var → prompt)
	TokenEnvFile   string `yaml:"token_env_file"`   // .env file path for token (PRIMARY - next 6 months)
	TokenEnvVar    string `yaml:"token_env_var"`    // Environment variable name for token
	TokenConsulKey string `yaml:"token_consul_key"` // Consul KV path for token (preferred long-term)
	TokenVaultPath string `yaml:"token_vault_path"` // Vault secret path for token

	// Base URL discovery (priority: env_file → consul → direct → env_var → prompt)
	BaseURLEnvFile   string `yaml:"base_url_env_file"`   // .env file path for base URL (PRIMARY - next 6 months)
	BaseURLEnvVar    string `yaml:"base_url_env_var"`    // Environment variable name for base URL
	BaseURLConsulKey string `yaml:"base_url_consul_key"` // Consul KV path for base URL

	// Basic auth (if type == basic)
	UsernameEnvVar string `yaml:"username_env_var"` // Basic auth username env var
	PasswordEnvVar string `yaml:"password_env_var"` // Basic auth password env var
}

// AuthType represents supported authentication types
type AuthType string

const (
	AuthTypeNone        AuthType = "none"         // No authentication (e.g., localhost-only APIs)
	AuthTypeBearerToken AuthType = "bearer_token" // Bearer token in Authorization header
	AuthTypeBasic       AuthType = "basic"        // HTTP Basic authentication
	AuthTypeAPIKey      AuthType = "api_key"      // API key in header or query param
)

// Resource defines a top-level API resource (e.g., users, groups, flows)
type Resource struct {
	Path         string               `yaml:"path"`         // Base path (e.g., /api/v3/core/users)
	Description  string               `yaml:"description"`  // Human-readable description
	Operations   map[string]Operation `yaml:"operations"`   // CRUD operations (list, get, create, update, delete)
	Subresources map[string]Resource  `yaml:"subresources"` // Nested resources (e.g., user permissions)
}

// Operation defines a single API operation (list, get, create, update, delete)
type Operation struct {
	Method         HTTPMethod  `yaml:"method"`          // HTTP method (GET, POST, PATCH, PUT, DELETE)
	Path           string      `yaml:"path"`            // Optional path override (e.g., /api/v3/core/users/{pk})
	Description    string      `yaml:"description"`     // Human-readable description
	Params         []Parameter `yaml:"params"`          // Path/query parameters (e.g., {pk}, ?is_superuser=true)
	Fields         []Field     `yaml:"fields"`          // Request body fields (for POST/PATCH/PUT)
	Filters        []Filter    `yaml:"filters"`         // Query filters (for GET list operations)
	OutputFields   []string    `yaml:"output_fields"`   // Fields to display in output (optional)
	Confirm        bool        `yaml:"confirm"`         // Require --force flag for destructive ops
	ConfirmMessage string      `yaml:"confirm_message"` // Custom confirmation prompt
	Returns        string      `yaml:"returns"`         // Description of return value
}

// HTTPMethod represents supported HTTP methods
type HTTPMethod string

const (
	HTTPMethodGET    HTTPMethod = "GET"
	HTTPMethodPOST   HTTPMethod = "POST"
	HTTPMethodPATCH  HTTPMethod = "PATCH"
	HTTPMethodPUT    HTTPMethod = "PUT"
	HTTPMethodDELETE HTTPMethod = "DELETE"
)

// Parameter defines a path or query parameter
// EXAMPLES:
//   - Path param: {pk} in /api/v3/core/users/{pk}
//   - Query param: ?is_superuser=true in /api/v3/core/users?is_superuser=true
type Parameter struct {
	Name        string        `yaml:"name"`        // Parameter name (e.g., "pk", "is_superuser")
	Type        ParameterType `yaml:"type"`        // Parameter type (uuid, string, boolean, etc.)
	Required    bool          `yaml:"required"`    // Is this parameter required?
	Description string        `yaml:"description"` // Human-readable description
	Default     interface{}   `yaml:"default"`     // Default value if not provided
	Values      []string      `yaml:"values"`      // Allowed values (for enum types)
}

// Field defines a request body field for POST/PATCH/PUT operations
type Field struct {
	Name        string        `yaml:"name"`        // Field name (e.g., "username", "email")
	Type        ParameterType `yaml:"type"`        // Field type (string, email, boolean, etc.)
	Required    bool          `yaml:"required"`    // Is this field required?
	Description string        `yaml:"description"` // Human-readable description
	Default     interface{}   `yaml:"default"`     // Default value if not provided
	Values      []string      `yaml:"values"`      // Allowed values (for enum types)
	HelpText    string        `yaml:"help_text"`   // Help text for interactive prompts
}

// Filter defines a query filter for list operations
// DIFFERENCE FROM PARAMETER: Filters are always optional, used for narrowing results
type Filter struct {
	Name        string        `yaml:"name"`        // Filter name (e.g., "is_superuser", "type")
	Type        ParameterType `yaml:"type"`        // Filter type (boolean, string, enum, etc.)
	Description string        `yaml:"description"` // Human-readable description
	Values      []string      `yaml:"values"`      // Allowed values (for enum types)
}

// ParameterType represents supported parameter/field types
type ParameterType string

const (
	ParameterTypeString   ParameterType = "string"   // Generic string
	ParameterTypeEmail    ParameterType = "email"    // Email address (validated)
	ParameterTypeUUID     ParameterType = "uuid"     // UUID (validated)
	ParameterTypeBoolean  ParameterType = "boolean"  // true/false
	ParameterTypeInteger  ParameterType = "integer"  // Integer number
	ParameterTypeFloat    ParameterType = "float"    // Floating point number
	ParameterTypeEnum     ParameterType = "enum"     // Enum (must be in Values list)
	ParameterTypeJSON     ParameterType = "json"     // JSON object/array
	ParameterTypePassword ParameterType = "password" // Password (no echo in prompts)
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// HTTP Client Interface (service-agnostic)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// HTTPClient is the interface for service-specific HTTP clients
// IMPLEMENTATIONS:
//   - pkg/authentik/unified_client.go (Authentik)
//   - pkg/wazuh/client.go (Wazuh, future)
//   - pkg/caddy/client.go (Caddy, future)
//
// RATIONALE: Allows framework to delegate HTTP transport to service-specific clients
// while maintaining consistent CRUD operations across all services
type HTTPClient interface {
	// DoRequest performs an HTTP request and returns the response body
	// PARAMETERS:
	//   - ctx: Context for request lifecycle, cancellation, tracing
	//   - method: HTTP method (GET, POST, PATCH, PUT, DELETE)
	//   - path: API path (e.g., /api/v3/core/users or /api/v3/core/users/{pk})
	//   - body: Request body (nil for GET/DELETE, map for POST/PATCH/PUT)
	// RETURNS: (responseBody []byte, error)
	DoRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Executor Results (runtime operation outputs)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// ListResult represents the result of a list operation
type ListResult struct {
	Items      []map[string]interface{} `json:"items"`       // List of resources
	TotalCount int                      `json:"total_count"` // Total number of results (from pagination)
	NextPage   string                   `json:"next_page"`   // URL for next page (if paginated)
}

// GetResult represents the result of a get operation
type GetResult struct {
	Item map[string]interface{} `json:"item"` // Single resource
}

// CreateResult represents the result of a create operation
type CreateResult struct {
	ID   interface{}            `json:"id"`   // Created resource ID (UUID, integer, etc.)
	Item map[string]interface{} `json:"item"` // Created resource (if API returns it)
}

// UpdateResult represents the result of an update operation
type UpdateResult struct {
	Item map[string]interface{} `json:"item"` // Updated resource (if API returns it)
}

// DeleteResult represents the result of a delete operation
type DeleteResult struct {
	Success bool   `json:"success"` // Was deletion successful?
	Message string `json:"message"` // Optional message from API
}
