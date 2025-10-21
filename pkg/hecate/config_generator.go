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
// - Assess: Prompt user for apps and their configuration
// - Intervene: Build configuration structure
// - Evaluate: Write YAML file and validate structure
func GenerateConfigFile(rc *eos_io.RuntimeContext, outputPath string, interactive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating Hecate configuration file",
		zap.String("output_path", outputPath),
		zap.Bool("interactive", interactive))

	var config RawYAMLConfig

	if interactive {
		logger.Info("terminal prompt: === Hecate Configuration Generator ===")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: This wizard will help you create a hecate-config.yaml file.")
		logger.Info("terminal prompt: You can add multiple apps. Press Enter to finish.")
		logger.Info("terminal prompt: ")

		apps, err := gatherApps(rc)
		if err != nil {
			return fmt.Errorf("failed to gather app configuration: %w", err)
		}
		config.Apps = apps
	} else {
		// Generate example config
		config = generateExampleConfig()
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
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt:   1. Review and edit: nano " + outputPath)
	logger.Info("terminal prompt:   2. Deploy infrastructure: eos create hecate --config " + outputPath)
	logger.Info("terminal prompt: ")

	return nil
}

// gatherApps prompts the user to add apps interactively
func gatherApps(rc *eos_io.RuntimeContext) (map[string]RawAppConfig, error) {
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

		// Check if already exists
		if _, exists := apps[appName]; exists {
			logger.Warn("App already configured, skipping",
				zap.String("app_name", appName))
			continue
		}

		app := RawAppConfig{}

		// Domain
		logger.Info("terminal prompt: Domain (e.g., example.com): ")
		fmt.Print("Domain: ")
		domainInput := strings.TrimSpace(mustReadLine(reader))
		if domainInput == "" {
			logger.Warn("Domain is required, skipping app")
			continue
		}

		// Sanitize domain input
		app.Domain = shared.SanitizeURL(domainInput)
		if app.Domain != domainInput {
			logger.Info("terminal prompt: ℹ️  Domain sanitized: " + app.Domain)
		}

		// Detect if this is authentik (special case)
		appType := DetectAppType(appName, "")
		if appType == "authentik" {
			logger.Info("terminal prompt: Detected Authentik SSO (backend is automatic)")
			apps[appName] = app
			continue
		}

		// Backend
		logger.Info("terminal prompt: Backend IP or IP:port (e.g., 192.168.1.100 or 192.168.1.100:8009): ")
		fmt.Print("Backend: ")
		app.Backend = strings.TrimSpace(mustReadLine(reader))
		if app.Backend == "" {
			logger.Warn("Backend is required, skipping app")
			continue
		}

		// Optional: Explicit type
		defaults := GetAppDefaults(appType)
		logger.Info(fmt.Sprintf("terminal prompt: App type (auto-detected: %s) [Enter to use auto-detection]: ", appType))
		fmt.Print("Type: ")
		explicitType := strings.TrimSpace(mustReadLine(reader))
		if explicitType != "" {
			app.Type = explicitType
		}

		// Optional: SSO
		if appType != "authentik" {
			logger.Info("terminal prompt: Enable SSO authentication? (y/N): ")
			fmt.Print("SSO: ")
			ssoInput := strings.TrimSpace(strings.ToLower(mustReadLine(reader)))
			app.SSO = (ssoInput == "y" || ssoInput == "yes")
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
