// pkg/apiclient/executor.go
// Runtime executor for declarative API client framework
//
// ARCHITECTURE: Interprets API definitions from YAML and executes CRUD operations
// HUMAN-CENTRIC: Interactive fallback, validation with remediation, structured logging
// SERVICE-AGNOSTIC: Works with any REST API (Authentik, Wazuh, Caddy, etc.)

package apiclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Executor - Core Business Logic
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Executor performs API operations based on declarative definitions
// ARCHITECTURE: Loads YAML definition → Discovers auth → Delegates to HTTPClient
// RESPONSIBILITY: Business logic ONLY - HTTP transport delegated to service clients
type Executor struct {
	definition *APIDefinition         // Loaded from YAML
	httpClient HTTPClient             // Service-specific transport (e.g., authentik.UnifiedClient)
	rc         *eos_io.RuntimeContext // For logging, tracing, secrets
}

// NewExecutor creates a new API executor for the given service
// FLOW:
//  1. Load API definition from YAML (pkg/[service]/api_definition.yaml)
//  2. Discover authentication token (env_file → consul → vault → prompt)
//  3. Discover base URL (env_file → consul → definition → prompt)
//  4. Create service-specific HTTP client (e.g., authentik.UnifiedClient)
//  5. Return initialized executor
//
// PARAMETERS:
//   - rc: RuntimeContext for logging, tracing, secrets
//   - service: Service name (e.g., "authentik", "wazuh")
//
// RETURNS: (*Executor, error)
//
// EXAMPLE:
//
//	executor, err := apiclient.NewExecutor(rc, "authentik")
//	if err != nil { ... }
//	result, err := executor.List(ctx, "users", filters)
func NewExecutor(rc *eos_io.RuntimeContext, service string) (*Executor, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Initializing API executor",
		zap.String("service", service))

	// Step 1: Load API definition from YAML
    definition, err := LoadDefinition(service)
    if err != nil {
        return nil, fmt.Errorf("failed to load API definition for %s: %w\n\n"+
            "Troubleshooting:\n"+
            "  1. Check if pkg/%s/api_definition.yaml exists\n"+
            "  2. Validate YAML syntax\n"+
            "  3. See pkg/apiclient/README.md for schema details",
            service, err, service)
    }

	logger.Debug("API definition loaded",
		zap.String("service", definition.Service),
		zap.String("version", definition.Version),
		zap.Int("resource_count", len(definition.Resources)))

	// Step 2: Discover authentication token
	// PRIORITY: env_file → consul → vault → env_var → prompt
    token, tokenSource, err := DiscoverAuthToken(rc, definition.Auth, service)
    if err != nil {
        return nil, fmt.Errorf("failed to discover authentication token for %s: %w\n\n"+
            "Troubleshooting:\n"+
            "  1. Check %s for %s\n"+
            "  2. Verify Consul KV key %s (if using Consul)\n"+
            "  3. Verify Vault path %s (if using Vault)\n"+
            "  4. Run: eos debug %s",
            service, err,
            definition.Auth.TokenEnvFile, definition.Auth.TokenEnvVar,
            definition.Auth.TokenConsulKey, definition.Auth.TokenVaultPath, service)
    }

	logger.Debug("Authentication token discovered",
		zap.String("source", tokenSource)) // NEVER log token value (P0 security)

	// Step 3: Discover base URL
	// PRIORITY: env_file → consul → definition.BaseURL → env_var → prompt
    baseURL, baseURLSource, err := DiscoverBaseURL(rc, definition.Auth, definition.BaseURL, service)
    if err != nil {
        return nil, fmt.Errorf("failed to discover base URL for %s: %w\n\n"+
            "Troubleshooting:\n"+
            "  1. Check %s for %s\n"+
            "  2. Verify Consul KV key %s (if using Consul)\n"+
            "  3. Set base_url in api_definition.yaml",
            service, err,
            definition.Auth.BaseURLEnvFile, definition.Auth.BaseURLEnvVar,
            definition.Auth.BaseURLConsulKey)
    }

	logger.Info("Base URL discovered",
		zap.String("base_url", baseURL),
		zap.String("source", baseURLSource))

	// Step 4: Create service-specific HTTP client
	// CRITICAL: This is the integration point with existing clients
	// For Authentik: Use pkg/authentik/unified_client.go
	// For other services: Implement HTTPClient interface
	var httpClient HTTPClient
	switch service {
	case "authentik":
		httpClient = authentik.NewUnifiedClient(baseURL, token)
		logger.Debug("Using Authentik unified client")
	default:
		return nil, fmt.Errorf("unsupported service: %s\n\n"+
			"Currently supported services:\n"+
			"  - authentik (uses pkg/authentik/unified_client.go)\n\n"+
			"To add support for %s:\n"+
			"  1. Create pkg/%s/client.go implementing HTTPClient interface\n"+
			"  2. Add case in pkg/apiclient/executor.go NewExecutor()\n"+
			"  3. Create pkg/%s/api_definition.yaml\n"+
			"See pkg/apiclient/README.md for details", service, service, service, service)
	}

	logger.Info("API executor initialized successfully",
		zap.String("service", service),
		zap.String("base_url", baseURL))

	return &Executor{
		definition: definition,
		httpClient: httpClient,
		rc:         rc,
	}, nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CRUD Operations
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// List retrieves a list of resources with optional filters
// FLOW:
//  1. Validate resource exists in definition
//  2. Validate operation exists for resource
//  3. Validate filters against operation definition
//  4. Build query string from filters
//  5. Execute GET request via httpClient
//  6. Parse response and extract pagination info
//
// PARAMETERS:
//   - ctx: Context for request lifecycle
//   - resource: Resource name (e.g., "users", "groups", "flows")
//   - filters: Optional filters (e.g., {"is_superuser": true, "type": "external"})
//
// RETURNS: (*ListResult, error)
//
// EXAMPLE:
//
//	result, err := executor.List(ctx, "users", map[string]interface{}{
//	    "is_superuser": true,
//	    "type": "external",
//	})
//	// result.Items = [{pk: "...", username: "alice", ...}, ...]
//	// result.TotalCount = 42
func (e *Executor) List(ctx context.Context, resource string, filters map[string]interface{}) (*ListResult, error) {
	logger := otelzap.Ctx(e.rc.Ctx)

	logger.Info("Executing list operation",
		zap.String("resource", resource),
		zap.Any("filters", filters))

	// Step 1: Get resource definition
	resourceDef, err := e.getResource(resource)
	if err != nil {
		return nil, err
	}

	// Step 2: Get list operation definition
	operation, err := e.getOperation(resourceDef, "list")
	if err != nil {
		return nil, err
	}

	// Step 3: Validate filters
	// Convert Filter definitions to Field definitions for validation
	// (filters are essentially optional fields in query params)
	filterFields := make([]Field, len(operation.Filters))
	for i, filter := range operation.Filters {
		filterFields[i] = Field{
			Name:        filter.Name,
			Type:        filter.Type,
			Required:    false, // Filters are always optional
			Description: filter.Description,
			Values:      filter.Values,
		}
	}
	if filterErrors := ValidateFields(filters, filterFields); len(filterErrors) > 0 {
		var errMsgs []string
		for field, err := range filterErrors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", field, err))
		}
		return nil, fmt.Errorf("filter validation failed:\n  %s", strings.Join(errMsgs, "\n  "))
	}

	// Step 4: Build query string
	queryString := buildQueryString(filters)

	// Step 5: Build request path
	path := resourceDef.Path
	if operation.Path != "" {
		path = operation.Path
	}
	if queryString != "" {
		path = path + "?" + queryString
	}

	logger.Debug("Built request path",
		zap.String("path", path),
		zap.String("method", string(operation.Method)))

	// Step 6: Execute HTTP request
	respBody, err := e.httpClient.DoRequest(ctx, string(operation.Method), path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %w\n\n"+
			"Request details:\n"+
			"  Method: %s\n"+
			"  Path: %s\n"+
			"  Filters: %v",
			resource, err, operation.Method, path, filters)
	}

	// Step 7: Parse response
	result, err := parseListResponse(respBody, operation.OutputFields)
	if err != nil {
		return nil, fmt.Errorf("failed to parse list response for %s: %w", resource, err)
	}

	logger.Info("List operation completed",
		zap.String("resource", resource),
		zap.Int("count", len(result.Items)),
		zap.Int("total", result.TotalCount),
		zap.Bool("has_next_page", result.NextPage != ""))

	return result, nil
}

// ListAll retrieves ALL pages of a list resource with pagination support
// FLOW:
//  1. Fetch first page via List()
//  2. If NextPage present, fetch subsequent pages
//  3. Accumulate all items across pages
//  4. Apply safety limit (max 100 pages = ~10,000 resources)
//
// PARAMETERS:
//   - ctx: Context for request lifecycle
//   - resource: Resource name (e.g., "users", "groups", "flows")
//   - filters: Optional filters (e.g., {"is_superuser": true})
//   - maxPages: Maximum pages to fetch (0 = unlimited, but enforces safety limit)
//
// RETURNS: (*ListResult, error)
//
// SECURITY: Implements DoS protection via maxPages limit
// RATIONALE: Prevents unbounded memory usage if attacker creates millions of resources
//
// EXAMPLE:
//
//	// Fetch all users (up to 100 pages = ~10,000 users)
//	result, err := executor.ListAll(ctx, "users", filters, 0)
//	// result.Items = all users across all pages
//	// result.TotalCount = actual total from API
func (e *Executor) ListAll(ctx context.Context, resource string, filters map[string]interface{}, maxPages int) (*ListResult, error) {
	logger := otelzap.Ctx(e.rc.Ctx)

	// SECURITY: Default safety limit prevents DoS via unbounded pagination
	const defaultMaxPages = 100 // Max 10,000 resources at 100 per page
	if maxPages <= 0 {
		maxPages = defaultMaxPages
	}
	if maxPages > defaultMaxPages {
		logger.Warn("Requested maxPages exceeds safety limit, capping",
			zap.Int("requested", maxPages),
			zap.Int("capped_to", defaultMaxPages))
		maxPages = defaultMaxPages
	}

	logger.Info("Executing list-all operation with pagination",
		zap.String("resource", resource),
		zap.Int("max_pages", maxPages),
		zap.Any("filters", filters))

	allItems := []map[string]interface{}{}
	totalCount := 0
	page := 1

	// Copy filters to avoid mutating caller's map
	pageFilters := make(map[string]interface{})
	for k, v := range filters {
		pageFilters[k] = v
	}

	for {
		// Add page number to filters if not first page
		if page > 1 {
			pageFilters["page"] = page
		}

		// Fetch current page
		result, err := e.List(ctx, resource, pageFilters)
		if err != nil {
			// PARTIAL RESULT: Return what we got so far + error
			logger.Warn("Pagination failed mid-fetch, returning partial results",
				zap.String("resource", resource),
				zap.Int("pages_fetched", page-1),
				zap.Int("items_fetched", len(allItems)),
				zap.Error(err))
			return &ListResult{
				Items:      allItems,
				TotalCount: totalCount,
				NextPage:   "",
			}, fmt.Errorf("pagination stopped at page %d: %w", page, err)
		}

		// Accumulate items
		allItems = append(allItems, result.Items...)
		totalCount = result.TotalCount

		logger.Debug("Fetched page",
			zap.Int("page", page),
			zap.Int("items_this_page", len(result.Items)),
			zap.Int("items_total", len(allItems)),
			zap.String("next_page", result.NextPage))

		// Check termination conditions
		if result.NextPage == "" || len(result.Items) == 0 {
			// No more pages
			logger.Info("Pagination complete (no more pages)",
				zap.String("resource", resource),
				zap.Int("pages_fetched", page),
				zap.Int("items_fetched", len(allItems)))
			break
		}

		if page >= maxPages {
			// Safety limit reached
			logger.Warn("Pagination safety limit reached, stopping",
				zap.String("resource", resource),
				zap.Int("pages_fetched", page),
				zap.Int("items_fetched", len(allItems)),
				zap.Int("limit", maxPages),
				zap.String("recommendation", "Increase maxPages or filter results"))
			break
		}

		page++
	}

	return &ListResult{
		Items:      allItems,
		TotalCount: totalCount,
		NextPage:   "", // All pages fetched
	}, nil
}

// Get retrieves a single resource by parameters (typically {pk})
// FLOW:
//  1. Validate resource exists in definition
//  2. Validate operation exists for resource
//  3. Validate params against operation definition
//  4. Build path with parameter substitution
//  5. Execute GET request via httpClient
//  6. Parse response
//
// PARAMETERS:
//   - ctx: Context for request lifecycle
//   - resource: Resource name (e.g., "users", "groups")
//   - params: Path parameters (e.g., {"pk": "123e4567-e89b-12d3-a456-426614174000"})
//
// RETURNS: (*GetResult, error)
//
// EXAMPLE:
//
//	result, err := executor.Get(ctx, "users", map[string]interface{}{
//	    "pk": "123e4567-e89b-12d3-a456-426614174000",
//	})
//	// result.Item = {pk: "...", username: "alice", email: "...", ...}
func (e *Executor) Get(ctx context.Context, resource string, params map[string]interface{}) (*GetResult, error) {
	logger := otelzap.Ctx(e.rc.Ctx)

	logger.Info("Executing get operation",
		zap.String("resource", resource),
		zap.Any("params", params))

	// Step 1: Get resource definition
	resourceDef, err := e.getResource(resource)
	if err != nil {
		return nil, err
	}

	// Step 2: Get get operation definition
	operation, err := e.getOperation(resourceDef, "get")
	if err != nil {
		return nil, err
	}

	// Step 3: Validate parameters
	if paramErrors := ValidateParameters(params, operation.Params); len(paramErrors) > 0 {
		var errMsgs []string
		for field, err := range paramErrors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", field, err))
		}
		return nil, fmt.Errorf("parameter validation failed:\n  %s", strings.Join(errMsgs, "\n  "))
	}

	// Step 4: Build path with parameter substitution
	path := operation.Path
	if path == "" {
		// Fallback: use resource path + first param value
		// Example: /api/v3/core/users + {pk} → /api/v3/core/users/{pk}
		path = resourceDef.Path
		for _, param := range operation.Params {
			if paramVal, ok := params[param.Name]; ok {
				path = fmt.Sprintf("%s/%v", path, paramVal)
				break
			}
		}
	} else {
		// Substitute path parameters: /api/v3/core/users/{pk} → /api/v3/core/users/123-uuid
		path = buildPath(path, params)
	}

	logger.Debug("Built request path",
		zap.String("path", path),
		zap.String("method", string(operation.Method)))

	// Step 5: Execute HTTP request
	respBody, err := e.httpClient.DoRequest(ctx, string(operation.Method), path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s: %w\n\n"+
			"Request details:\n"+
			"  Method: %s\n"+
			"  Path: %s\n"+
			"  Params: %v",
			resource, err, operation.Method, path, params)
	}

	// Step 6: Parse response
	item, err := parseItemResponse(respBody, operation.OutputFields)
	if err != nil {
		return nil, fmt.Errorf("failed to parse get response for %s: %w", resource, err)
	}

	logger.Info("Get operation completed",
		zap.String("resource", resource))

	return &GetResult{Item: item}, nil
}

// Create creates a new resource with the given fields
// FLOW:
//  1. Validate resource exists in definition
//  2. Validate operation exists for resource
//  3. Validate fields against operation definition
//  4. Convert fields to typed values
//  5. Execute POST request via httpClient
//  6. Parse response and extract created ID
//
// PARAMETERS:
//   - ctx: Context for request lifecycle
//   - resource: Resource name (e.g., "users", "groups")
//   - fields: Field values (e.g., {"username": "alice", "email": "alice@example.com", "type": "external"})
//
// RETURNS: (*CreateResult, error)
//
// EXAMPLE:
//
//	result, err := executor.Create(ctx, "users", map[string]interface{}{
//	    "username": "alice",
//	    "email": "alice@example.com",
//	    "type": "external",
//	})
//	// result.ID = "123e4567-e89b-12d3-a456-426614174000"
//	// result.Item = {pk: "...", username: "alice", ...}
func (e *Executor) Create(ctx context.Context, resource string, fields map[string]interface{}) (*CreateResult, error) {
	logger := otelzap.Ctx(e.rc.Ctx)

	logger.Info("Executing create operation",
		zap.String("resource", resource),
		zap.Any("fields", fields))

	// Step 1: Get resource definition
	resourceDef, err := e.getResource(resource)
	if err != nil {
		return nil, err
	}

	// Step 2: Get create operation definition
	operation, err := e.getOperation(resourceDef, "create")
	if err != nil {
		return nil, err
	}

	// Step 3: Validate fields
	if fieldErrors := ValidateFields(fields, operation.Fields); len(fieldErrors) > 0 {
		var errMsgs []string
		for field, err := range fieldErrors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", field, err))
		}
		return nil, fmt.Errorf("field validation failed:\n  %s", strings.Join(errMsgs, "\n  "))
	}

	// Step 4: Build request path
	path := resourceDef.Path
	if operation.Path != "" {
		path = operation.Path
	}

	logger.Debug("Built request path",
		zap.String("path", path),
		zap.String("method", string(operation.Method)))

	// Step 5: Execute HTTP request
	respBody, err := e.httpClient.DoRequest(ctx, string(operation.Method), path, fields)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s: %w\n\n"+
			"Request details:\n"+
			"  Method: %s\n"+
			"  Path: %s\n"+
			"  Fields: %v",
			resource, err, operation.Method, path, fields)
	}

	// Step 6: Parse response and extract ID
	item, err := parseItemResponse(respBody, operation.OutputFields)
	if err != nil {
		return nil, fmt.Errorf("failed to parse create response for %s: %w", resource, err)
	}

	// Extract ID from response (typically "pk", "id", or "uuid" field)
	var id interface{}
	for _, idField := range []string{"pk", "id", "uuid"} {
		if val, ok := item[idField]; ok {
			id = val
			break
		}
	}

	logger.Info("Create operation completed",
		zap.String("resource", resource),
		zap.Any("id", id))

	return &CreateResult{
		ID:   id,
		Item: item,
	}, nil
}

// Update updates an existing resource with the given fields
// FLOW:
//  1. Validate resource exists in definition
//  2. Validate operation exists for resource
//  3. Validate params against operation definition
//  4. Validate fields against operation definition
//  5. Build path with parameter substitution
//  6. Execute PATCH/PUT request via httpClient
//  7. Parse response
//
// PARAMETERS:
//   - ctx: Context for request lifecycle
//   - resource: Resource name (e.g., "users", "groups")
//   - params: Path parameters (e.g., {"pk": "123e4567-e89b-12d3-a456-426614174000"})
//   - fields: Field values to update (e.g., {"type": "internal", "is_active": true})
//
// RETURNS: (*UpdateResult, error)
//
// EXAMPLE:
//
//	result, err := executor.Update(ctx, "users",
//	    map[string]interface{}{"pk": "123e4567-e89b-12d3-a456-426614174000"},
//	    map[string]interface{}{"type": "internal", "is_active": true})
//	// result.Item = {pk: "...", username: "alice", type: "internal", is_active: true, ...}
func (e *Executor) Update(ctx context.Context, resource string, params map[string]interface{}, fields map[string]interface{}) (*UpdateResult, error) {
	logger := otelzap.Ctx(e.rc.Ctx)

	logger.Info("Executing update operation",
		zap.String("resource", resource),
		zap.Any("params", params),
		zap.Any("fields", fields))

	// Step 1: Get resource definition
	resourceDef, err := e.getResource(resource)
	if err != nil {
		return nil, err
	}

	// Step 2: Get update operation definition
	operation, err := e.getOperation(resourceDef, "update")
	if err != nil {
		return nil, err
	}

	// Step 3: Validate parameters
	if paramErrors := ValidateParameters(params, operation.Params); len(paramErrors) > 0 {
		var errMsgs []string
		for field, err := range paramErrors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", field, err))
		}
		return nil, fmt.Errorf("parameter validation failed:\n  %s", strings.Join(errMsgs, "\n  "))
	}

	// Step 4: Validate fields
	if fieldErrors := ValidateFields(fields, operation.Fields); len(fieldErrors) > 0 {
		var errMsgs []string
		for field, err := range fieldErrors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", field, err))
		}
		return nil, fmt.Errorf("field validation failed:\n  %s", strings.Join(errMsgs, "\n  "))
	}

	// Step 5: Build path with parameter substitution
	path := operation.Path
	if path == "" {
		// Fallback: use resource path + first param value
		path = resourceDef.Path
		for _, param := range operation.Params {
			if paramVal, ok := params[param.Name]; ok {
				path = fmt.Sprintf("%s/%v", path, paramVal)
				break
			}
		}
	} else {
		path = buildPath(path, params)
	}

	logger.Debug("Built request path",
		zap.String("path", path),
		zap.String("method", string(operation.Method)))

	// Step 6: Execute HTTP request
	respBody, err := e.httpClient.DoRequest(ctx, string(operation.Method), path, fields)
	if err != nil {
		return nil, fmt.Errorf("failed to update %s: %w\n\n"+
			"Request details:\n"+
			"  Method: %s\n"+
			"  Path: %s\n"+
			"  Params: %v\n"+
			"  Fields: %v",
			resource, err, operation.Method, path, params, fields)
	}

	// Step 7: Parse response
	item, err := parseItemResponse(respBody, operation.OutputFields)
	if err != nil {
		return nil, fmt.Errorf("failed to parse update response for %s: %w", resource, err)
	}

	logger.Info("Update operation completed",
		zap.String("resource", resource))

	return &UpdateResult{Item: item}, nil
}

// Delete deletes a resource by parameters (typically {pk})
// FLOW:
//  1. Validate resource exists in definition
//  2. Validate operation exists for resource
//  3. Validate params against operation definition
//  4. Check if confirmation required
//  5. Build path with parameter substitution
//  6. Execute DELETE request via httpClient
//
// PARAMETERS:
//   - ctx: Context for request lifecycle
//   - resource: Resource name (e.g., "users", "groups")
//   - params: Path parameters (e.g., {"pk": "123e4567-e89b-12d3-a456-426614174000"})
//
// RETURNS: (*DeleteResult, error)
//
// EXAMPLE:
//
//	result, err := executor.Delete(ctx, "users", map[string]interface{}{
//	    "pk": "123e4567-e89b-12d3-a456-426614174000",
//	})
//	// result.Success = true
func (e *Executor) Delete(ctx context.Context, resource string, params map[string]interface{}) (*DeleteResult, error) {
	logger := otelzap.Ctx(e.rc.Ctx)

	logger.Info("Executing delete operation",
		zap.String("resource", resource),
		zap.Any("params", params))

	// Step 1: Get resource definition
	resourceDef, err := e.getResource(resource)
	if err != nil {
		return nil, err
	}

	// Step 2: Get delete operation definition
	operation, err := e.getOperation(resourceDef, "delete")
	if err != nil {
		return nil, err
	}

	// Step 3: Validate parameters
	if paramErrors := ValidateParameters(params, operation.Params); len(paramErrors) > 0 {
		var errMsgs []string
		for field, err := range paramErrors {
			errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", field, err))
		}
		return nil, fmt.Errorf("parameter validation failed:\n  %s", strings.Join(errMsgs, "\n  "))
	}

	// Step 4: Check if confirmation required
	// NOTE: Confirmation is handled by the CLI command layer (cmd/delete/*.go)
	// This executor only performs the operation - it's the command's responsibility
	// to check operation.Confirm and require --force flag
	if operation.Confirm {
		logger.Debug("Delete operation requires confirmation (check handled by CLI layer)")
	}

	// Step 5: Build path with parameter substitution
	path := operation.Path
	if path == "" {
		// Fallback: use resource path + first param value
		path = resourceDef.Path
		for _, param := range operation.Params {
			if paramVal, ok := params[param.Name]; ok {
				path = fmt.Sprintf("%s/%v", path, paramVal)
				break
			}
		}
	} else {
		path = buildPath(path, params)
	}

	logger.Debug("Built request path",
		zap.String("path", path),
		zap.String("method", string(operation.Method)))

	// Step 6: Execute HTTP request
	_, err = e.httpClient.DoRequest(ctx, string(operation.Method), path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to delete %s: %w\n\n"+
			"Request details:\n"+
			"  Method: %s\n"+
			"  Path: %s\n"+
			"  Params: %v",
			resource, err, operation.Method, path, params)
	}

	logger.Info("Delete operation completed",
		zap.String("resource", resource))

	return &DeleteResult{Success: true}, nil
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// getResource retrieves a resource definition from the loaded API definition
func (e *Executor) getResource(resourceName string) (*Resource, error) {
	resource, ok := e.definition.Resources[resourceName]
	if !ok {
		availableResources := make([]string, 0, len(e.definition.Resources))
		for name := range e.definition.Resources {
			availableResources = append(availableResources, name)
		}
		return nil, fmt.Errorf("unknown resource: %s\n\n"+
			"Available resources for %s:\n"+
			"  %s",
			resourceName, e.definition.Service, strings.Join(availableResources, ", "))
	}
	return &resource, nil
}

// getOperation retrieves an operation definition from a resource
func (e *Executor) getOperation(resource *Resource, operationName string) (*Operation, error) {
	operation, ok := resource.Operations[operationName]
	if !ok {
		availableOps := make([]string, 0, len(resource.Operations))
		for name := range resource.Operations {
			availableOps = append(availableOps, name)
		}
		return nil, fmt.Errorf("operation %s not supported for resource\n\n"+
			"Available operations:\n"+
			"  %s",
			operationName, strings.Join(availableOps, ", "))
	}
	return &operation, nil
}

// buildPath builds a request path with parameter substitution
// EXAMPLE: buildPath("/api/v3/core/users/{pk}", {pk: "123-uuid"}) → "/api/v3/core/users/123-uuid"
func buildPath(template string, params map[string]interface{}) string {
	path := template
	for key, val := range params {
		placeholder := fmt.Sprintf("{%s}", key)
		path = strings.ReplaceAll(path, placeholder, fmt.Sprintf("%v", val))
	}
	return path
}

// buildQueryString builds a URL query string from filters
// EXAMPLE: buildQueryString({is_superuser: true, type: "external"}) → "is_superuser=true&type=external"
func buildQueryString(filters map[string]interface{}) string {
	if len(filters) == 0 {
		return ""
	}

	values := url.Values{}
	for key, val := range filters {
		values.Add(key, fmt.Sprintf("%v", val))
	}
	return values.Encode()
}

// parseListResponse parses a list API response and extracts items and pagination info
// ARCHITECTURE: Handles Authentik pagination format with "results", "pagination.count", "pagination.next"
// EXTENSIBILITY: Can be enhanced to support other pagination formats (e.g., HAL, JSON:API)
func parseListResponse(respBody []byte, outputFields []string) (*ListResult, error) {
	var response map[string]interface{}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w\n\nResponse body:\n%s",
			err, string(respBody))
	}

	// Extract items (Authentik uses "results" field)
	var items []map[string]interface{}
	if resultsRaw, ok := response["results"]; ok {
		if resultsSlice, ok := resultsRaw.([]interface{}); ok {
			for _, itemRaw := range resultsSlice {
				if itemMap, ok := itemRaw.(map[string]interface{}); ok {
					items = append(items, itemMap)
				}
			}
		}
	} else {
		// Fallback: response is a plain array
		var plainArray []map[string]interface{}
		if err := json.Unmarshal(respBody, &plainArray); err == nil {
			items = plainArray
		}
	}

	// Extract pagination info (Authentik uses "pagination.count" and "pagination.next")
	totalCount := len(items) // Fallback: count items if pagination not present
	if pagination, ok := response["pagination"].(map[string]interface{}); ok {
		if count, ok := pagination["count"].(float64); ok {
			totalCount = int(count)
		}
	}

	// P0 FIX: Authentik returns next page as integer (page number), not string (URL)
	// RATIONALE: Authentik pagination format uses page numbers: {"next": 2, "previous": null}
	// SECURITY: Prevents silent pagination failure that would lose data
	nextPage := ""
	if pagination, ok := response["pagination"].(map[string]interface{}); ok {
		// Try float64 first (JSON numbers are float64)
		if next, ok := pagination["next"].(float64); ok && next > 0 {
			nextPage = fmt.Sprintf("page=%d", int(next))
		} else if next, ok := pagination["next"].(int); ok && next > 0 {
			// Fallback: direct int (shouldn't happen with JSON, but be defensive)
			nextPage = fmt.Sprintf("page=%d", next)
		}
	}

	return &ListResult{
		Items:      items,
		TotalCount: totalCount,
		NextPage:   nextPage,
	}, nil
}

// parseItemResponse parses a single-item API response
func parseItemResponse(respBody []byte, outputFields []string) (map[string]interface{}, error) {
	var item map[string]interface{}
	if err := json.Unmarshal(respBody, &item); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w\n\nResponse body:\n%s",
			err, string(respBody))
	}

	return item, nil
}
