// pkg/hecate/yaml_config.go

package hecate

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// RawAppConfig represents a single app as defined in the YAML config
type RawAppConfig struct {
	Domain  string `yaml:"domain"`
	Backend string `yaml:"backend"`
	Type    string `yaml:"type,omitempty"`
	SSO     bool   `yaml:"sso,omitempty"`
	Talk    bool   `yaml:"talk,omitempty"`
}

// RawYAMLConfig represents the top-level YAML structure
type RawYAMLConfig struct {
	Apps map[string]RawAppConfig `yaml:"apps"`
}

// AppConfig represents a fully parsed and resolved app configuration
type AppConfig struct {
	Name            string
	Type            string
	Domain          string
	Backend         string
	BackendPort     int
	BackendProtocol string
	TLSSkipVerify   bool
	WebSocket       bool
	HealthCheck     string
	LogLevel        string
	TCPPorts        map[int]int
	SSO             bool
	SSOPublicPaths  []string
	Talk            bool
	RequiresCoturn  bool
	DockerDeps      []string
}

// YAMLHecateConfig represents the complete parsed and validated configuration
type YAMLHecateConfig struct {
	Apps            map[string]AppConfig
	HasAuthentik    bool
	NeedsCoturn     bool
	NeedsNginx      bool
	AuthentikDomain string
}

// LoadYAMLConfig reads and parses a YAML configuration file
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Read and parse YAML file
// - Intervene: Parse each app with type detection and defaults
// - Evaluate: Validate configuration and track infrastructure needs
func LoadYAMLConfig(rc *eos_io.RuntimeContext, configPath string) (*YAMLHecateConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Loading Hecate YAML configuration",
		zap.String("config_path", configPath))

	// ASSESS - Read YAML file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, eos_err.NewUserError(
				"Configuration file not found: %s\n\n"+
					"To create a new configuration:\n"+
					"  1. Generate interactively: eos create config --hecate\n"+
					"  2. Or copy example: cp examples/hecate-config.yaml %s\n"+
					"  3. Then edit: nano %s\n\n"+
					"See examples/hecate-config.yaml for configuration format",
				configPath, configPath, configPath)
		}
		if os.IsPermission(err) {
			return nil, eos_err.NewUserError(
				"Permission denied reading config file: %s\n"+
					"Fix: chmod +r %s", configPath, configPath)
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	var raw RawYAMLConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, eos_err.NewUserError(
			"Failed to parse YAML configuration file: %s\n\n"+
				"Error: %v\n\n"+
				"Common issues:\n"+
				"  - Invalid YAML syntax (check indentation)\n"+
				"  - Missing required fields (domain, backend)\n"+
				"  - Invalid field names\n\n"+
				"Validate YAML syntax: https://www.yamllint.com/\n"+
				"See examples/hecate-config.yaml for correct format",
			configPath, err)
	}

	config := &YAMLHecateConfig{
		Apps: make(map[string]AppConfig),
	}

	// INTERVENE - Parse each app
	for appName, rawApp := range raw.Apps {
		app, err := parseApp(rc, appName, rawApp)
		if err != nil {
			return nil, fmt.Errorf("error parsing app '%s': %w", appName, err)
		}

		config.Apps[appName] = app

		// Track infrastructure needs
		if app.Type == "authentik" {
			config.HasAuthentik = true
			config.AuthentikDomain = app.Domain
		}
		if app.RequiresCoturn {
			config.NeedsCoturn = true
		}
		if len(app.TCPPorts) > 0 {
			config.NeedsNginx = true
		}
	}

	// EVALUATE - Validate SSO requirements
	for appName, app := range config.Apps {
		if app.SSO && !config.HasAuthentik {
			return nil, eos_err.NewUserError(
				"App '%s' requires SSO but no Authentik instance is configured.\n\n"+
					"SSO (Single Sign-On) authentication requires Authentik to be deployed.\n\n"+
					"Fix this by choosing ONE of these options:\n\n"+
					"OPTION 1: Disable SSO for this app (simplest)\n"+
					"  Edit your config file: %s\n"+
					"  Change the '%s' app to:\n"+
					"    sso: false\n\n"+
					"OPTION 2: Add Authentik to your config (enables SSO)\n"+
					"  Add this to your config file under 'apps:':\n"+
					"    authentik:\n"+
					"      domain: auth.%s  # Your SSO login domain\n"+
					"      # Note: Backend is automatic, no need to specify\n\n"+
					"OPTION 3: Regenerate config with Authentik included\n"+
					"  1. Run: eos create config --hecate\n"+
					"  2. When prompted, add an 'authentik' app FIRST\n"+
					"  3. Then enable SSO (sso: y) for apps that need it\n\n"+
					"For more info: https://goauthentik.io/docs/",
				appName, configPath, appName, extractBaseDomain(app.Domain),
			)
		}
	}

	logger.Info("YAML configuration loaded successfully",
		zap.Int("app_count", len(config.Apps)),
		zap.Bool("has_authentik", config.HasAuthentik),
		zap.Bool("needs_coturn", config.NeedsCoturn),
		zap.Bool("needs_nginx", config.NeedsNginx))

	return config, nil
}

// parseApp converts a raw app config into a fully resolved AppConfig
func parseApp(rc *eos_io.RuntimeContext, appName string, rawApp RawAppConfig) (AppConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Detect app type
	appType := DetectAppType(appName, rawApp.Type)
	defaults := GetAppDefaults(appType)

	logger.Debug("Parsing app configuration",
		zap.String("app_name", appName),
		zap.String("detected_type", appType))

	// Validate and sanitize required fields
	if rawApp.Domain == "" {
		return AppConfig{}, fmt.Errorf("missing required field: domain")
	}

	// Sanitize domain input
	sanitizedDomain := shared.SanitizeURL(rawApp.Domain)
	if sanitizedDomain != rawApp.Domain {
		logger.Debug("Domain sanitized",
			zap.String("original", rawApp.Domain),
			zap.String("sanitized", sanitizedDomain))
	}

	// Validate domain format
	if err := validateDomain(sanitizedDomain); err != nil {
		return AppConfig{}, fmt.Errorf("invalid domain for app '%s': %w", appName, err)
	}

	// SPECIAL CASE: Authentik is always internal
	if appType == "authentik" {
		if rawApp.Backend != "" {
			return AppConfig{}, fmt.Errorf(
				"authentik backend is automatic (hecate-server-1:9000). Do not specify backend",
			)
		}

		return AppConfig{
			Name:            appName,
			Type:            "authentik",
			Domain:          sanitizedDomain,
			Backend:         "hecate-server-1",
			BackendPort:     shared.PortAuthentik,
			BackendProtocol: "http",
			WebSocket:       true,
			LogLevel:        "DEBUG",
			HealthCheck:     "/-/health/live/",
			DockerDeps:      defaults.DockerDeps,
			SSO:             false,
		}, nil
	}

	// Normal apps require backend
	if rawApp.Backend == "" {
		return AppConfig{}, fmt.Errorf("missing required field: backend")
	}

	// Validate backend format
	if err := validateBackend(rawApp.Backend); err != nil {
		return AppConfig{}, fmt.Errorf("invalid backend for app '%s': %w", appName, err)
	}

	// Parse backend (host:port or just host)
	backendHost, backendPort := parseBackend(rawApp.Backend, defaults.BackendPort, appType, appName)

	app := AppConfig{
		Name:            appName,
		Type:            appType,
		Domain:          sanitizedDomain,
		Backend:         backendHost,
		BackendPort:     backendPort,
		BackendProtocol: defaults.BackendProtocol,
		TLSSkipVerify:   defaults.TLSSkipVerify,
		WebSocket:       defaults.WebSocket,
		HealthCheck:     defaults.HealthCheck,
		LogLevel:        defaults.LogLevel,
		TCPPorts:        copyIntMap(defaults.TCPPorts),
		SSO:             rawApp.SSO,
		SSOPublicPaths:  append([]string{}, defaults.SSOPublicPaths...),
		Talk:            rawApp.Talk,
		RequiresCoturn:  rawApp.Talk,
		DockerDeps:      append([]string{}, defaults.DockerDeps...),
	}

	return app, nil
}

// parseBackend extracts host and port from backend string
func parseBackend(backend string, defaultPort int, appType string, appName string) (string, int) {
	// Check if backend includes port
	if strings.Contains(backend, ":") {
		parts := strings.Split(backend, ":")
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err == nil {
				return parts[0], port
			}
		}
	}

	// MinIO special case: detect API port
	if appType == "minio" && strings.Contains(strings.ToLower(appName), "api") {
		return backend, shared.PortMinioAPI
	}

	return backend, defaultPort
}

// copyIntMap creates a deep copy of an int-to-int map
func copyIntMap(m map[int]int) map[int]int {
	if m == nil {
		return nil
	}
	result := make(map[int]int, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// validateBackend checks if backend is a valid IP address or hostname
func validateBackend(backend string) error {
	if backend == "" {
		return fmt.Errorf("backend cannot be empty")
	}

	// Extract host part (remove :port if present)
	host := backend
	if strings.Contains(backend, ":") {
		parts := strings.Split(backend, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid backend format (too many colons): %s", backend)
		}
		host = parts[0]

		// Validate port
		port := parts[1]
		if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
			return fmt.Errorf("invalid port number: %s (must be 1-65535)", port)
		}
	}

	// Check if it's a valid format (IP or hostname)
	// Allow: IPs (192.168.1.1), hostnames (server.local), FQDNs (app.example.com)
	// Reject: URLs with protocols, paths, queries
	if strings.Contains(host, "/") || strings.Contains(host, "?") ||
		strings.Contains(host, "@") || strings.Contains(host, "#") {
		return fmt.Errorf("invalid backend format: %s\n"+
			"Use IP address (192.168.1.100) or hostname (server.local)\n"+
			"Do not include protocol (http://), path (/api), or query (?key=val)", backend)
	}

	// Very basic hostname/IP validation - just check reasonable characters
	validChars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"
	for _, char := range host {
		if !strings.ContainsRune(validChars, char) {
			return fmt.Errorf("invalid character '%c' in backend: %s\n"+
				"Backend must be IP address or hostname (alphanumeric, dots, hyphens only)",
				char, backend)
		}
	}

	return nil
}

// extractBaseDomain extracts the base domain from a subdomain
// e.g., "delphi.cybermonkey.net.au" -> "cybermonkey.net.au"
func extractBaseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain // Already a base domain
	}
	// Return last two parts (handles .com, .net, etc.)
	// For .co.uk, .net.au, etc., this is still reasonable
	return strings.Join(parts[len(parts)-2:], ".")
}

// validateDomain checks if domain is a valid format
func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Remove protocol if accidentally included
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		return fmt.Errorf("domain should not include protocol: %s\n"+
			"Use: example.com (not https://example.com)", domain)
	}

	// Check for path, query, or fragment
	if strings.Contains(domain, "/") || strings.Contains(domain, "?") || strings.Contains(domain, "#") {
		return fmt.Errorf("domain should not include path, query, or fragment: %s\n"+
			"Use: example.com (not example.com/path)", domain)
	}

	// Check for spaces or other invalid characters
	if strings.Contains(domain, " ") || strings.Contains(domain, "\t") {
		return fmt.Errorf("domain contains whitespace: %s", domain)
	}

	// Very basic domain validation - must have at least one dot for FQDN
	// (Allow localhost, etc. for development)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 && domain != "localhost" {
		return fmt.Errorf("invalid domain format: %s\n"+
			"Use fully qualified domain name (example.com)\n"+
			"or 'localhost' for local development", domain)
	}

	return nil
}
