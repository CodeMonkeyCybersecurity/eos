// pkg/hecate/config_generator.go

package hecate

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// GenerateConfigFile creates a Hecate YAML configuration file interactively
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check for previous config in Consul KV, prompt user for apps
// - Intervene: Build configuration structure, store in Consul KV
// - Evaluate: Write YAML file and validate structure
func GenerateConfigFile(rc *eos_io.RuntimeContext, outputPath string, interactive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating Hecate configuration file",
		zap.String("output_path", outputPath),
		zap.Bool("interactive", interactive))

	// Try to initialize Consul KV storage (non-fatal if unavailable)
	configStorage, err := NewConfigStorage(rc)
	if err != nil {
		logger.Warn("Consul KV not available, configuration will not be persisted",
			zap.Error(err))
		// Continue without Consul storage
	}

	var config RawYAMLConfig

	if interactive {
		logger.Info("terminal prompt: === Hecate Configuration Generator ===")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: This wizard will help you create a hecate-config.yaml file.")
		logger.Info("terminal prompt: You can add multiple apps. Press Enter to finish.")
		logger.Info("terminal prompt: ")

		// Load previous config from Consul KV if available
		var previousConfig *RawYAMLConfig
		if configStorage != nil {
			previousConfig, _ = configStorage.LoadConfig(rc)
			if previousConfig != nil && len(previousConfig.Apps) > 0 {
				logger.Info("terminal prompt: ℹ️  Found previous configuration in Consul KV")
				logger.Info("terminal prompt: Previous apps:")
				for appName, app := range previousConfig.Apps {
					logger.Info(fmt.Sprintf("terminal prompt:   - %s (domain: %s)", appName, app.Domain))
				}
				logger.Info("terminal prompt: ")
			}
		}

		apps, err := gatherApps(rc, previousConfig)
		if err != nil {
			return fmt.Errorf("failed to gather app configuration: %w", err)
		}
		config.Apps = apps
	} else {
		// Generate example config
		config = generateExampleConfig()
	}

	// Store configuration in Consul KV (if available)
	if configStorage != nil {
		if err := configStorage.StoreConfig(rc, config); err != nil {
			logger.Warn("Failed to store configuration in Consul KV",
				zap.Error(err))
			// Continue even if Consul storage fails
		} else {
			logger.Info("Configuration stored in Consul KV",
				zap.Int("apps", len(config.Apps)))
		}
	}

	// Write YAML file
	if err := writeYAMLConfig(config, outputPath); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("Configuration file created successfully",
		zap.String("path", outputPath),
		zap.Int("app_count", len(config.Apps)))

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ Configuration file created: " + outputPath)
	if configStorage != nil {
		logger.Info("terminal prompt: ✓ Configuration stored in Consul KV for future use")
	}
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt:   1. Review and edit: nano " + outputPath)
	logger.Info("terminal prompt:   2. Deploy infrastructure: eos create hecate --config " + outputPath)
	logger.Info("terminal prompt: ")

	return nil
}

// gatherApps prompts the user to add apps interactively
func gatherApps(rc *eos_io.RuntimeContext, previousConfig *RawYAMLConfig) (map[string]RawAppConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	reader := bufio.NewReader(os.Stdin)
	apps := make(map[string]RawAppConfig)

	for {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: --- Add Application ---")

		// App name
		logger.Info("terminal prompt: App name (e.g., main, wazuh, nextcloud) [Enter to finish]: ")
		fmt.Print("App name: ")
		appName := strings.TrimSpace(mustReadLine(reader))
		if appName == "" {
			break
		}

		// Check if already exists in current session
		if _, exists := apps[appName]; exists {
			logger.Warn("App already configured in this session, skipping",
				zap.String("app_name", appName))
			continue
		}

		app := RawAppConfig{}

		// Check for previous config defaults
		var previousApp *RawAppConfig
		if previousConfig != nil {
			if prevApp, exists := previousConfig.Apps[appName]; exists {
				previousApp = &prevApp
				logger.Info("terminal prompt: ℹ️  Found previous config for '" + appName + "'")
			}
		}

		// Domain (with validation retry loop)
		defaultDomain := ""
		if previousApp != nil {
			defaultDomain = previousApp.Domain
		}

		// Loop until valid domain is provided
		for {
			if defaultDomain != "" {
				logger.Info(fmt.Sprintf("terminal prompt: Domain (e.g., example.com) [%s]: ", defaultDomain))
			} else {
				logger.Info("terminal prompt: Domain (e.g., example.com): ")
			}
			fmt.Print("Domain: ")
			domainInput := strings.TrimSpace(mustReadLine(reader))

			// Use default if empty
			if domainInput == "" {
				if defaultDomain != "" {
					domainInput = defaultDomain
					logger.Info("terminal prompt: Using previous domain: " + defaultDomain)
				} else {
					logger.Info("terminal prompt: ❌ Domain is required (cannot be empty)")
					logger.Info("terminal prompt: ")
					continue
				}
			}

			// Sanitize domain input
			sanitizedDomain := shared.SanitizeURL(domainInput)
			if sanitizedDomain != domainInput {
				logger.Info("terminal prompt: ℹ️  Domain sanitized: " + sanitizedDomain)
			}

			// Validate domain format
			if err := validateDomain(sanitizedDomain); err != nil {
				logger.Info("terminal prompt: ")
				logger.Info(fmt.Sprintf("terminal prompt: ❌ Invalid domain: %v", err))
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: Examples of valid domains:")
				logger.Info("terminal prompt:   - example.com")
				logger.Info("terminal prompt:   - subdomain.example.com")
				logger.Info("terminal prompt:   - app.cybermonkey.net.au")
				logger.Info("terminal prompt: ")
				continue
			}

			// Valid domain
			app.Domain = sanitizedDomain
			break
		}

		// Detect if this is authentik (special case)
		appType := DetectAppType(appName, "")
		if appType == "authentik" {
			logger.Info("terminal prompt: Detected Authentik SSO (backend is automatic)")
			apps[appName] = app
			continue
		}

		// Backend (with validation retry loop)
		defaultBackend := ""
		if previousApp != nil {
			defaultBackend = previousApp.Backend
		}

		// Loop until valid backend is provided
		for {
			if defaultBackend != "" {
				logger.Info(fmt.Sprintf("terminal prompt: Backend IP or IP:port [%s]: ", defaultBackend))
			} else {
				logger.Info("terminal prompt: Backend IP or IP:port (e.g., 192.168.1.100 or 192.168.1.100:8009): ")
			}
			fmt.Print("Backend: ")
			backendInput := strings.TrimSpace(mustReadLine(reader))

			// Use default if empty
			if backendInput == "" {
				if defaultBackend != "" {
					backendInput = defaultBackend
					logger.Info("terminal prompt: Using previous backend: " + defaultBackend)
				} else {
					logger.Info("terminal prompt: ❌ Backend is required (cannot be empty)")
					logger.Info("terminal prompt: ")
					continue
				}
			}

			// Validate backend format
			if err := validateBackend(backendInput); err != nil {
				logger.Info("terminal prompt: ")
				logger.Info(fmt.Sprintf("terminal prompt: ❌ Invalid backend: %v", err))
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: Examples of valid backends:")
				logger.Info("terminal prompt:   - 192.168.1.100 (IP address)")
				logger.Info("terminal prompt:   - 192.168.1.100:8009 (IP:port)")
				logger.Info("terminal prompt:   - 100.88.69.11 (Tailscale IP)")
				logger.Info("terminal prompt:   - server.local (hostname)")
				logger.Info("terminal prompt: ")
				continue
			}

			// Valid backend
			app.Backend = backendInput
			break
		}

		// Optional: Explicit type (with default from previous config)
		defaults := GetAppDefaults(appType)
		defaultType := ""
		if previousApp != nil && previousApp.Type != "" {
			defaultType = previousApp.Type
		}
		if defaultType != "" {
			logger.Info(fmt.Sprintf("terminal prompt: App type (auto-detected: %s) [%s]: ", appType, defaultType))
		} else {
			logger.Info(fmt.Sprintf("terminal prompt: App type (auto-detected: %s) [Enter to use auto-detection]: ", appType))
		}
		fmt.Print("Type: ")
		explicitType := strings.TrimSpace(mustReadLine(reader))
		if explicitType != "" {
			app.Type = explicitType
		} else if defaultType != "" {
			app.Type = defaultType
		}

		// Optional: SSO (with default from previous config)
		if appType != "authentik" {
			defaultSSO := false
			if previousApp != nil {
				defaultSSO = previousApp.SSO
			}
			ssoDefault := "N"
			if defaultSSO {
				ssoDefault = "y"
			}
			logger.Info(fmt.Sprintf("terminal prompt: Enable SSO authentication? (y/N) [%s]: ", ssoDefault))
			fmt.Print("SSO: ")
			ssoInput := strings.TrimSpace(strings.ToLower(mustReadLine(reader)))
			if ssoInput == "" {
				app.SSO = defaultSSO
			} else {
				app.SSO = (ssoInput == "y" || ssoInput == "yes")
			}
		}

		// Optional: WebRTC/Talk (for Nextcloud)
		if appType == "nextcloud" {
			logger.Info("terminal prompt: Enable Nextcloud Talk (WebRTC/Coturn)? (y/N): ")
			fmt.Print("Talk: ")
			talkInput := strings.TrimSpace(strings.ToLower(mustReadLine(reader)))
			app.Talk = (talkInput == "y" || talkInput == "yes")
		}

		apps[appName] = app

		logger.Info("terminal prompt: ✓ Added: " + appName + " (" + appType + ")")
		logger.Info(fmt.Sprintf("terminal prompt:   Domain: %s", app.Domain))
		logger.Info(fmt.Sprintf("terminal prompt:   Backend: %s:%d", app.Backend, defaults.BackendPort))
		if app.SSO {
			logger.Info("terminal prompt:   SSO: enabled")
		}
		if app.Talk {
			logger.Info("terminal prompt:   Talk: enabled")
		}
	}

	if len(apps) == 0 {
		return nil, fmt.Errorf("no apps configured")
	}

	// Validate SSO requirements early (BLOCKING validation)
	hasAuthentik := false
	appsRequiringSSO := []string{}

	for appName, app := range apps {
		if DetectAppType(appName, app.Type) == "authentik" {
			hasAuthentik = true
		}
		if app.SSO {
			appsRequiringSSO = append(appsRequiringSSO, appName)
		}
	}

	// BLOCKING: Force Authentik configuration if SSO is enabled
	if len(appsRequiringSSO) > 0 && !hasAuthentik {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: ⚠️  SSO Configuration Required")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: The following apps have SSO enabled:")
		for _, appName := range appsRequiringSSO {
			logger.Info("terminal prompt:   - " + appName)
		}
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: SSO authentication requires Authentik to be configured.")
		logger.Info("terminal prompt: You MUST provide an Authentik domain to continue.")
		logger.Info("terminal prompt: ")

		reader := bufio.NewReader(os.Stdin)

		// Loop until valid Authentik domain is provided
		for {
			logger.Info("terminal prompt: Authentik domain (e.g., auth.example.com): ")
			fmt.Print("Domain: ")
			authentikDomain := strings.TrimSpace(mustReadLine(reader))

			if authentikDomain == "" {
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: ❌ Domain is required for SSO to work.")
				logger.Info("terminal prompt: ")
				logger.Info("terminal prompt: Options:")
				logger.Info("terminal prompt:   1. Enter a domain (e.g., auth.cybermonkey.net.au)")
				logger.Info("terminal prompt:   2. Exit and manually disable SSO in your config file")
				logger.Info("terminal prompt: ")
				continue // Keep looping until they provide a domain
			}

			// Validate domain format
			sanitizedDomain := shared.SanitizeURL(authentikDomain)
			if err := validateDomain(sanitizedDomain); err != nil {
				logger.Info("terminal prompt: ")
				logger.Info(fmt.Sprintf("terminal prompt: ❌ Invalid domain: %v", err))
				logger.Info("terminal prompt: ")
				continue // Keep looping until valid domain
			}

			// Valid domain provided - add Authentik
			apps["authentik"] = RawAppConfig{
				Domain: sanitizedDomain,
			}
			logger.Info("terminal prompt: ")
			logger.Info("terminal prompt: ✓ Added Authentik SSO")
			logger.Info("terminal prompt:   Domain: " + apps["authentik"].Domain)
			logger.Info("terminal prompt:   Backend: hecate-server-1:9000 (automatic)")
			break // Exit the loop
		}
	}

	logger.Info("terminal prompt: ")
	logger.Info(fmt.Sprintf("terminal prompt: Total apps configured: %d", len(apps)))

	return apps, nil
}

// generateExampleConfig creates an example configuration
func generateExampleConfig() RawYAMLConfig {
	return RawYAMLConfig{
		Apps: map[string]RawAppConfig{
			"main": {
				Domain:  "example.com",
				Backend: "192.168.1.100:8009",
			},
			"wazuh": {
				Domain:  "wazuh.example.com",
				Backend: "192.168.1.101",
			},
			"nextcloud": {
				Domain:  "cloud.example.com",
				Backend: "192.168.1.100",
				SSO:     true,
				Talk:    true,
			},
			"authentik": {
				Domain: "auth.example.com",
			},
		},
	}
}

// writeYAMLConfig writes the configuration to a YAML file
func writeYAMLConfig(config RawYAMLConfig, outputPath string) error {
	data, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// Add header comment
	header := `# Hecate Configuration
# Generated by: eos create config --hecate
#
# Usage: eos create hecate --config hecate-config.yaml
#
# This configuration defines your reverse proxy infrastructure:
# - Each app gets automatic HTTPS via Caddy
# - Authentik provides SSO for apps with sso: true
# - Nextcloud Talk enables WebRTC/Coturn if talk: true
# - Wazuh automatically includes TCP ports (1514, 1515, 55000)
#
# For more examples, see: examples/hecate-config.yaml

`

	fullData := []byte(header + string(data))

	if err := os.WriteFile(outputPath, fullData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// mustReadLine reads a line from stdin, returns empty string on error
func mustReadLine(reader *bufio.Reader) string {
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(input)
}
