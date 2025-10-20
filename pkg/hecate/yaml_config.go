// pkg/hecate/yaml_config.go

package hecate

import (
	"fmt"
	"os"
	"strconv"
	"strings"

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
	Name              string
	Type              string
	Domain            string
	Backend           string
	BackendPort       int
	BackendProtocol   string
	TLSSkipVerify     bool
	WebSocket         bool
	HealthCheck       string
	LogLevel          string
	TCPPorts          map[int]int
	SSO               bool
	SSOPublicPaths    []string
	Talk              bool
	RequiresCoturn    bool
	DockerDeps        []string
}

// YAMLHecateConfig represents the complete parsed and validated configuration
type YAMLHecateConfig struct {
	Apps              map[string]AppConfig
	HasAuthentik      bool
	NeedsCoturn       bool
	NeedsNginx        bool
	AuthentikDomain   string
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
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var raw RawYAMLConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
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
			return nil, fmt.Errorf(
				"app '%s' has sso=true but no authentik app configured. "+
					"Add an authentik app to your config", appName,
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

	// Validate required fields
	if rawApp.Domain == "" {
		return AppConfig{}, fmt.Errorf("missing required field: domain")
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
			Domain:          rawApp.Domain,
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

	// Parse backend (host:port or just host)
	backendHost, backendPort := parseBackend(rawApp.Backend, defaults.BackendPort, appType, appName)

	app := AppConfig{
		Name:            appName,
		Type:            appType,
		Domain:          rawApp.Domain,
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
