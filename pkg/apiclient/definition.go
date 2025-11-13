// pkg/apiclient/definition.go
// YAML API definition loader
//
// ARCHITECTURE: Loads declarative API definitions from YAML files
// LOCATION: Definitions stored in pkg/[service]/api_definition.yaml
// CACHING: Definitions cached in memory after first load
// VALIDATION: Schema validation on load (required fields, valid types)

package apiclient

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Definition Loading (with caching)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

var (
	// definitionCache caches loaded API definitions to avoid repeated YAML parsing
	// KEY: service name (e.g., "authentik", "wazuh", "caddy")
	// VALUE: parsed APIDefinition struct
	definitionCache = make(map[string]*APIDefinition)
	cacheMu         sync.RWMutex
)

// LoadDefinition loads an API definition from YAML file
// CACHING: Definitions cached after first load (call ClearCache() to reload)
// SEARCH ORDER:
//  1. pkg/[service]/api_definition.yaml (embedded in binary)
//  2. /etc/eos/api_definitions/[service].yaml (user overrides)
//  3. ~/.eos/api_definitions/[service].yaml (user overrides)
//
// Parameters:
//   - service: Service name (e.g., "authentik", "wazuh", "caddy")
//
// Returns: (*APIDefinition, error)
//
// Example:
//
//	def, err := apiclient.LoadDefinition("authentik")
//	if err != nil {
//	    return fmt.Errorf("failed to load Authentik API definition: %w", err)
//	}
func LoadDefinition(service string) (*APIDefinition, error) {
	// Check cache first
	cacheMu.RLock()
	if cached, ok := definitionCache[service]; ok {
		cacheMu.RUnlock()
		return cached, nil
	}
	cacheMu.RUnlock()

	// Try loading from various locations
	var def *APIDefinition
	var err error

	// 1. Try user override in /etc/eos/api_definitions/
	systemPath := filepath.Join("/etc/eos/api_definitions", service+".yaml")
	if fileExists(systemPath) {
		def, err = loadDefinitionFromFile(systemPath)
		if err == nil {
			cacheMu.Lock()
			definitionCache[service] = def
			cacheMu.Unlock()
			return def, nil
		}
	}

	// 2. Try user override in ~/.eos/api_definitions/
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		userPath := filepath.Join(homeDir, ".eos", "api_definitions", service+".yaml")
		if fileExists(userPath) {
			def, err = loadDefinitionFromFile(userPath)
			if err == nil {
				cacheMu.Lock()
				definitionCache[service] = def
				cacheMu.Unlock()
				return def, nil
			}
		}
	}

	// 3. Try embedded definition (default)
    def, err = loadEmbeddedDefinition(service)
    if err != nil {
        return nil, fmt.Errorf("failed to load API definition for %s: %w\n"+
            "Searched:\n"+
            "  - %s (not found or invalid)\n"+
            "  - ~/.eos/api_definitions/%s.yaml (not found or invalid)\n"+
            "  - embedded definitions (not found)\n"+
            "Create API definition in one of these locations.",
            service, err, systemPath, service)
    }

	// Cache and return
	cacheMu.Lock()
	definitionCache[service] = def
	cacheMu.Unlock()

	return def, nil
}

// loadDefinitionFromFile loads API definition from a file path
func loadDefinitionFromFile(path string) (*APIDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var def APIDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate definition
	if err := validateDefinition(&def); err != nil {
		return nil, fmt.Errorf("invalid API definition: %w", err)
	}

	return &def, nil
}

// loadEmbeddedDefinition loads API definition from embedded files
// IMPLEMENTATION NOTE: This will be populated when we embed API definition files
// For now, returns error if service not found
func loadEmbeddedDefinition(service string) (*APIDefinition, error) {
	// TODO: Implement embedded file loading with go:embed
	// Example:
	//   //go:embed definitions/*.yaml
	//   var embeddedDefinitions embed.FS
	//
	//   data, err := embeddedDefinitions.ReadFile(fmt.Sprintf("definitions/%s.yaml", service))
	//   if err != nil {
	//       return nil, fmt.Errorf("service %s not found in embedded definitions", service)
	//   }
	//   ... parse YAML ...

	return nil, fmt.Errorf("embedded definitions not yet implemented (service: %s)", service)
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ClearCache clears the definition cache (useful for testing or hot-reloading)
func ClearCache() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	definitionCache = make(map[string]*APIDefinition)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Definition Validation
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// validateDefinition validates an API definition
// VALIDATES:
//   - Service name present
//   - At least one resource defined
//   - All operations have valid HTTP methods
//   - All parameters/fields have valid types
//   - No duplicate resource names
func validateDefinition(def *APIDefinition) error {
	if def.Service == "" {
		return fmt.Errorf("service name is required")
	}

	if len(def.Resources) == 0 {
		return fmt.Errorf("at least one resource is required")
	}

	// Validate each resource
	for resName, resource := range def.Resources {
		if err := validateResource(resName, &resource); err != nil {
			return fmt.Errorf("resource %q: %w", resName, err)
		}
	}

	return nil
}

// validateResource validates a single resource definition
func validateResource(name string, res *Resource) error {
	if res.Path == "" {
		return fmt.Errorf("path is required")
	}

	if len(res.Operations) == 0 {
		return fmt.Errorf("at least one operation is required")
	}

	// Validate each operation
	for opName, op := range res.Operations {
		if err := validateOperation(opName, &op); err != nil {
			return fmt.Errorf("operation %q: %w", opName, err)
		}
	}

	// Validate subresources (recursively)
	for subName, subRes := range res.Subresources {
		if err := validateResource(subName, &subRes); err != nil {
			return fmt.Errorf("subresource %q: %w", subName, err)
		}
	}

	return nil
}

// validateOperation validates a single operation definition
func validateOperation(name string, op *Operation) error {
	// Validate HTTP method
	validMethods := map[HTTPMethod]bool{
		HTTPMethodGET:    true,
		HTTPMethodPOST:   true,
		HTTPMethodPATCH:  true,
		HTTPMethodPUT:    true,
		HTTPMethodDELETE: true,
	}

	if !validMethods[op.Method] {
		return fmt.Errorf("invalid HTTP method: %s (must be GET, POST, PATCH, PUT, or DELETE)", op.Method)
	}

	// Validate parameters
	for i, param := range op.Params {
		if err := validateParameter(i, &param); err != nil {
			return fmt.Errorf("parameter %d: %w", i, err)
		}
	}

	// Validate fields
	for i, field := range op.Fields {
		if err := validateField(i, &field); err != nil {
			return fmt.Errorf("field %d: %w", i, err)
		}
	}

	// Validate filters
	for i, filter := range op.Filters {
		if err := validateFilter(i, &filter); err != nil {
			return fmt.Errorf("filter %d: %w", i, err)
		}
	}

	return nil
}

// validateParameter validates a parameter definition
func validateParameter(index int, param *Parameter) error {
	if param.Name == "" {
		return fmt.Errorf("name is required")
	}

	if !isValidParameterType(param.Type) {
		return fmt.Errorf("invalid type: %s", param.Type)
	}

	// Enum type must have values
	if param.Type == ParameterTypeEnum && len(param.Values) == 0 {
		return fmt.Errorf("enum type requires values list")
	}

	return nil
}

// validateField validates a field definition
func validateField(index int, field *Field) error {
	if field.Name == "" {
		return fmt.Errorf("name is required")
	}

	if !isValidParameterType(field.Type) {
		return fmt.Errorf("invalid type: %s", field.Type)
	}

	// Enum type must have values
	if field.Type == ParameterTypeEnum && len(field.Values) == 0 {
		return fmt.Errorf("enum type requires values list")
	}

	return nil
}

// validateFilter validates a filter definition
func validateFilter(index int, filter *Filter) error {
	if filter.Name == "" {
		return fmt.Errorf("name is required")
	}

	if !isValidParameterType(filter.Type) {
		return fmt.Errorf("invalid type: %s", filter.Type)
	}

	return nil
}

// isValidParameterType checks if a parameter type is valid
func isValidParameterType(t ParameterType) bool {
	validTypes := map[ParameterType]bool{
		ParameterTypeString:   true,
		ParameterTypeEmail:    true,
		ParameterTypeUUID:     true,
		ParameterTypeBoolean:  true,
		ParameterTypeInteger:  true,
		ParameterTypeFloat:    true,
		ParameterTypeEnum:     true,
		ParameterTypeJSON:     true,
		ParameterTypePassword: true,
	}

	return validTypes[t]
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Helper Functions
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// GetOperation retrieves an operation from a definition
// HANDLES: Nested resources (e.g., "users.permissions.list")
//
// Parameters:
//   - def: API definition
//   - resource: Resource name (e.g., "users" or "users.permissions")
//   - operation: Operation name (e.g., "list", "get", "create")
//
// Returns: (*Operation, error)
func GetOperation(def *APIDefinition, resource, operation string) (*Operation, error) {
	// TODO: Implement nested resource path parsing
	// For now, simple lookup
	res, ok := def.Resources[resource]
	if !ok {
		return nil, fmt.Errorf("resource %q not found", resource)
	}

	op, ok := res.Operations[operation]
	if !ok {
		return nil, fmt.Errorf("operation %q not found for resource %q", operation, resource)
	}

	return &op, nil
}

// ListResources returns all resource names in a definition
func ListResources(def *APIDefinition) []string {
	resources := make([]string, 0, len(def.Resources))
	for name := range def.Resources {
		resources = append(resources, name)
	}
	return resources
}

// ListOperations returns all operation names for a resource
func ListOperations(def *APIDefinition, resource string) ([]string, error) {
	res, ok := def.Resources[resource]
	if !ok {
		return nil, fmt.Errorf("resource %q not found", resource)
	}

	operations := make([]string, 0, len(res.Operations))
	for name := range res.Operations {
		operations = append(operations, name)
	}
	return operations, nil
}
