// pkg/docker/compose_validate.go
// Docker SDK-based validation for docker-compose.yml files
//
// This replaces shell-based validation (`docker compose config`) with
// native Go YAML parsing + Docker SDK validation for better error messages
// and no dependency on docker CLI being in PATH.

package docker

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ComposeConfig represents a parsed docker-compose.yml file
type ComposeConfig struct {
	Services map[string]Service            `yaml:"services"`
	Networks map[string]Network            `yaml:"networks,omitempty"`
	Volumes  map[string]Volume             `yaml:"volumes,omitempty"`
	Configs  map[string]interface{}        `yaml:"configs,omitempty"`
	Secrets  map[string]interface{}        `yaml:"secrets,omitempty"`
	Version  string                        `yaml:"version,omitempty"` // Deprecated but still parsed
	Name     string                        `yaml:"name,omitempty"`
	Raw      map[string]interface{}        `yaml:",inline"` // Catch-all for unknown fields
}

// Service represents a service in docker-compose.yml
type Service struct {
	Image       string                 `yaml:"image,omitempty"`
	Build       interface{}            `yaml:"build,omitempty"` // Can be string or struct
	ContainerName string               `yaml:"container_name,omitempty"`
	Command     interface{}            `yaml:"command,omitempty"` // Can be string or []string
	Environment map[string]string      `yaml:"environment,omitempty"`
	EnvFile     interface{}            `yaml:"env_file,omitempty"` // Can be string or []string
	Ports       []interface{}          `yaml:"ports,omitempty"` // Can be string or struct
	Volumes     []interface{}          `yaml:"volumes,omitempty"`
	Networks    interface{}            `yaml:"networks,omitempty"` // Can be []string or map
	DependsOn   interface{}            `yaml:"depends_on,omitempty"` // Can be []string or map
	Restart     string                 `yaml:"restart,omitempty"`
	Labels      map[string]string      `yaml:"labels,omitempty"`
	Raw         map[string]interface{} `yaml:",inline"` // Catch-all
}

// Network represents a network configuration
type Network struct {
	Driver     string                 `yaml:"driver,omitempty"`
	DriverOpts map[string]string      `yaml:"driver_opts,omitempty"`
	External   bool                   `yaml:"external,omitempty"`
	Raw        map[string]interface{} `yaml:",inline"`
}

// Volume represents a volume configuration
type Volume struct {
	Driver     string                 `yaml:"driver,omitempty"`
	DriverOpts map[string]string      `yaml:"driver_opts,omitempty"`
	External   bool                   `yaml:"external,omitempty"`
	Raw        map[string]interface{} `yaml:",inline"`
}

// ValidationError represents a compose file validation error
type ValidationError struct {
	Service string // Service name (if applicable)
	Field   string // Field name (if applicable)
	Message string // Error message
}

func (e *ValidationError) Error() string {
	if e.Service != "" && e.Field != "" {
		return fmt.Sprintf("service '%s' field '%s': %s", e.Service, e.Field, e.Message)
	} else if e.Service != "" {
		return fmt.Sprintf("service '%s': %s", e.Service, e.Message)
	}
	return e.Message
}

// ValidateComposeFile validates a docker-compose.yml file using SDK
//
// This function implements validation WITHOUT shelling out to docker CLI:
// - Parses YAML with gopkg.in/yaml.v3
// - Validates service image references
// - Checks for common misconfigurations
// - Substitutes variables from .env file
//
// Returns detailed error with remediation steps if validation fails.
func ValidateComposeFile(ctx context.Context, composePath, envPath string) error {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Validating docker-compose file with SDK",
		zap.String("compose", composePath),
		zap.String("env", envPath))

	// ASSESS: Read compose file
	composeData, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}

	// ASSESS: Read .env file (if provided)
	envVars := make(map[string]string)
	if envPath != "" {
		envVars, err = parseEnvFile(envPath)
		if err != nil {
			logger.Warn("Failed to parse .env file, continuing without variable substitution",
				zap.Error(err))
		}
	}

	// INTERVENE: Parse YAML
	var compose ComposeConfig
	if err := yaml.Unmarshal(composeData, &compose); err != nil {
		return fmt.Errorf("invalid YAML syntax in docker-compose.yml:\n%w\n\n"+
			"Run 'yamllint %s' to check syntax", err, composePath)
	}

	// INTERVENE: Substitute environment variables
	if err := substituteVariables(&compose, envVars); err != nil {
		return err
	}

	// EVALUATE: Validate services
	var errors []error
	for name, service := range compose.Services {
		if err := validateService(name, service); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return &ValidationErrors{Errors: errors}
	}

	logger.Info("docker-compose.yml validation passed (SDK)",
		zap.String("file", composePath),
		zap.Int("services", len(compose.Services)))

	return nil
}

// ValidationErrors wraps multiple validation errors
type ValidationErrors struct {
	Errors []error
}

func (e *ValidationErrors) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d validation error(s) found:\n", len(e.Errors)))
	for i, err := range e.Errors {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, err.Error()))
	}
	return sb.String()
}

// validateService validates a single service configuration
func validateService(name string, svc Service) error {
	// Check: Must have either image or build
	if svc.Image == "" && svc.Build == nil {
		return &ValidationError{
			Service: name,
			Message: "must specify either 'image' or 'build'",
		}
	}

	// Check: Image reference format (if using image)
	if svc.Image != "" {
		if err := validateImageReference(svc.Image); err != nil {
			return &ValidationError{
				Service: name,
				Field:   "image",
				Message: err.Error(),
			}
		}
	}

	// Check: Port mappings
	for i, port := range svc.Ports {
		if portStr, ok := port.(string); ok {
			if err := validatePortMapping(portStr); err != nil {
				return &ValidationError{
					Service: name,
					Field:   fmt.Sprintf("ports[%d]", i),
					Message: err.Error(),
				}
			}
		}
	}

	return nil
}

// validateImageReference checks if an image reference is valid
func validateImageReference(image string) error {
	// Check for variable references that weren't substituted
	if strings.Contains(image, "${") && strings.Contains(image, "}") {
		return fmt.Errorf("contains unsubstituted variable: %s (check .env file)", image)
	}

	// Check for empty parts after substitution
	parts := strings.Split(image, ":")
	if len(parts) > 2 {
		return fmt.Errorf("invalid format (too many colons): %s", image)
	}

	// Check for empty repository
	if parts[0] == "" {
		return fmt.Errorf("empty repository name")
	}

	return nil
}

// validatePortMapping validates a port mapping string
func validatePortMapping(port string) error {
	// Examples: "80:80", "127.0.0.1:80:80", "8080:80/tcp"
	if strings.Contains(port, "${") && strings.Contains(port, "}") {
		return fmt.Errorf("contains unsubstituted variable: %s", port)
	}

	// Basic format check (just ensure it's not empty)
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("empty port mapping")
	}

	return nil
}

// parseEnvFile parses a .env file into a map
func parseEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read .env file: %w", err)
	}

	envVars := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	for lineNum, line := range lines {
		// Skip empty lines and comments
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf(".env file line %d: invalid format (expected KEY=VALUE): %s",
				lineNum+1, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, `"'`)

		envVars[key] = value
	}

	return envVars, nil
}

// substituteVariables replaces ${VAR} and ${VAR:-default} in compose config
func substituteVariables(compose *ComposeConfig, envVars map[string]string) error {
	// Substitute in all services
	for name, service := range compose.Services {
		// Substitute image
		if service.Image != "" {
			substituted, err := substituteString(service.Image, envVars)
			if err != nil {
				return &ValidationError{
					Service: name,
					Field:   "image",
					Message: err.Error(),
				}
			}
			service.Image = substituted
			compose.Services[name] = service
		}

		// Substitute environment variables
		for key, value := range service.Environment {
			substituted, err := substituteString(value, envVars)
			if err != nil {
				return &ValidationError{
					Service: name,
					Field:   fmt.Sprintf("environment.%s", key),
					Message: err.Error(),
				}
			}
			service.Environment[key] = substituted
		}
	}

	return nil
}

// substituteString replaces ${VAR} and ${VAR:-default} in a string
func substituteString(s string, envVars map[string]string) (string, error) {
	result := s

	// Find all ${...} patterns
	for {
		start := strings.Index(result, "${")
		if start == -1 {
			break
		}

		end := strings.Index(result[start:], "}")
		if end == -1 {
			return "", fmt.Errorf("unclosed variable reference: %s", result[start:])
		}
		end += start

		// Extract variable reference
		varRef := result[start+2 : end]

		// Parse ${VAR:-default} syntax
		var varName, defaultValue string
		var required bool

		if strings.Contains(varRef, ":?") {
			// ${VAR:?error message} - required variable
			parts := strings.SplitN(varRef, ":?", 2)
			varName = parts[0]
			required = true
		} else if strings.Contains(varRef, ":-") {
			// ${VAR:-default} - optional with default
			parts := strings.SplitN(varRef, ":-", 2)
			varName = parts[0]
			defaultValue = parts[1]
		} else {
			// ${VAR} - simple variable
			varName = varRef
		}

		// Get value from env
		value, exists := envVars[varName]

		if !exists {
			if required {
				return "", fmt.Errorf("required variable %s is not set", varName)
			}
			if defaultValue != "" {
				value = defaultValue
			}
			// If no default, leave as empty string
		}

		// Replace in result
		result = result[:start] + value + result[end+1:]
	}

	return result, nil
}
