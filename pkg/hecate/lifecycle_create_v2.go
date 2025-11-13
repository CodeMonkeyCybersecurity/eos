// pkg/hecate/lifecycle_create_v2.go

package hecate

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// DeploymentMethod represents how Hecate should be deployed
type DeploymentMethod string

const (
	DeploymentMethodDefault DeploymentMethod = ""
	DeploymentMethodDocker  DeploymentMethod = "docker"
	DeploymentMethodManual  DeploymentMethod = "manual"
)

// HecateDeploymentConfig holds configuration for the deployment
type HecateDeploymentConfig struct {
	Method         DeploymentMethod
	Domain         string
	AdminEmail     string
	EnableAuth     bool
	EnableMetrics  bool
	CustomCertPath string
	CustomKeyPath  string
	DNSProvider    string
	DNSAPIToken    string
}

// OrchestrateHecateDeployment is the new main entry point for Hecate deployment
func OrchestrateHecateDeployment(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Hecate deployment orchestration")

	// Collect deployment configuration
	config, err := collectDeploymentConfig(rc)
	if err != nil {
		return fmt.Errorf("failed to collect deployment configuration: %w", err)
	}

	// Deploy based on selected method
	switch config.Method {
	case DeploymentMethodDefault:
		logger.Info("Default deployment requires administrator intervention")
		return fmt.Errorf("Default deployment has been migrated to HashiCorp stack. Please use Docker or Manual deployment methods, or contact your administrator for system-level deployment assistance")

	case DeploymentMethodDocker:
		logger.Info("Deploying Hecate with Docker Compose")
		// Fall back to existing wizard for now
		return OrchestrateHecateWizard(rc)

	case DeploymentMethodManual:
		logger.Info("Manual deployment selected")
		return provideManualInstructions(rc)

	default:
		return eos_err.NewUserError("invalid deployment method selected")
	}
}

// collectDeploymentConfig interactively collects deployment configuration
func collectDeploymentConfig(rc *eos_io.RuntimeContext) (*HecateDeploymentConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	config := &HecateDeploymentConfig{
		EnableAuth:    true,
		EnableMetrics: true,
	}

	logger.Info("terminal prompt: Welcome to Hecate Deployment")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Select deployment method:")
	logger.Info("terminal prompt:   1.  (recommended for production)")
	logger.Info("terminal prompt:   2. Docker Compose (for development)")
	logger.Info("terminal prompt:   3. Manual (show instructions)")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Enter choice [1-3] (default: 1):")

	choice, err := eos_io.ReadInput(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read deployment method: %w", err)
	}

	switch strings.TrimSpace(choice) {
	case "2":
		config.Method = DeploymentMethodDocker
	case "3":
		config.Method = DeploymentMethodManual
	default:
		config.Method = DeploymentMethodDefault
	}

	// Only collect additional config for non-manual deployments
	if config.Method != DeploymentMethodManual {
		// Domain configuration
		logger.Info("terminal prompt: Enter your primary domain (e.g., example.com):")
		domain, err := eos_io.ReadInput(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read domain: %w", err)
		}
		config.Domain = strings.TrimSpace(domain)

		if config.Domain == "" {
			config.Domain = "localhost"
			logger.Info("Using default domain: localhost")
		}

		// Admin email
		logger.Info("terminal prompt: Enter admin email for Let's Encrypt (optional):")
		email, err := eos_io.ReadInput(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read email: %w", err)
		}
		config.AdminEmail = strings.TrimSpace(email)

		// DNS provider for wildcard certs
		if config.Domain != "localhost" {
			logger.Info("terminal prompt: Configure DNS provider for wildcard certificates? [y/N]:")
			dnsChoice, err := eos_io.ReadInput(rc)
			if err != nil {
				return nil, fmt.Errorf("failed to read DNS choice: %w", err)
			}

			if strings.ToLower(strings.TrimSpace(dnsChoice)) == "y" {
				logger.Info("terminal prompt: Select DNS provider:")
				logger.Info("terminal prompt:   1. Hetzner")
				logger.Info("terminal prompt:   2. Cloudflare")
				logger.Info("terminal prompt:   3. Route53")
				logger.Info("terminal prompt:   4. Manual DNS")
				logger.Info("terminal prompt: Enter choice [1-4]:")

				providerChoice, err := eos_io.ReadInput(rc)
				if err != nil {
					return nil, fmt.Errorf("failed to read DNS provider: %w", err)
				}

				switch strings.TrimSpace(providerChoice) {
				case "1":
					config.DNSProvider = "hetzner"
					logger.Info("terminal prompt: Enter Hetzner DNS API token:")
					token, err := eos_io.PromptSecurePassword(rc, "Enter Hetzner DNS API token:")
					if err != nil {
						return nil, fmt.Errorf("failed to read API token: %w", err)
					}
					config.DNSAPIToken = token
				case "2":
					config.DNSProvider = "cloudflare"
				case "3":
					config.DNSProvider = "route53"
				default:
					config.DNSProvider = "manual"
				}
			}
		}

		// Authentication
		logger.Info("terminal prompt: Enable authentication with Authentik? [Y/n]:")
		authChoice, err := eos_io.ReadInput(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read auth choice: %w", err)
		}
		config.EnableAuth = strings.ToLower(strings.TrimSpace(authChoice)) != "n"

		// Metrics
		logger.Info("terminal prompt: Enable metrics collection? [Y/n]:")
		metricsChoice, err := eos_io.ReadInput(rc)
		if err != nil {
			return nil, fmt.Errorf("failed to read metrics choice: %w", err)
		}
		config.EnableMetrics = strings.ToLower(strings.TrimSpace(metricsChoice)) != "n"
	}

	// Display configuration summary
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Configuration Summary:")
	logger.Info("terminal prompt: =====================")
	logger.Info("terminal prompt: Deployment Method: " + string(config.Method))
	if config.Method != DeploymentMethodManual {
		logger.Info("terminal prompt: Domain: " + config.Domain)
		logger.Info("terminal prompt: Admin Email: " + config.AdminEmail)
		logger.Info("terminal prompt: Enable Auth: " + fmt.Sprintf("%v", config.EnableAuth))
		logger.Info("terminal prompt: Enable Metrics: " + fmt.Sprintf("%v", config.EnableMetrics))
		if config.DNSProvider != "" {
			logger.Info("terminal prompt: DNS Provider: " + config.DNSProvider)
		}
	}
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Proceed with deployment? [Y/n]:")

	proceed, err := eos_io.ReadInput(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read confirmation: %w", err)
	}

	if strings.ToLower(strings.TrimSpace(proceed)) == "n" {
		return nil, eos_err.NewUserError("deployment cancelled by user")
	}

	// Store configuration in Vault if using default method
	if config.Method == DeploymentMethodDefault {
		if err := storeConfigInVault(rc, config); err != nil {
			return nil, fmt.Errorf("failed to store configuration: %w", err)
		}
	}

	return config, nil
}

// storeConfigInVault saves deployment configuration to Vault
func storeConfigInVault(rc *eos_io.RuntimeContext, config *HecateDeploymentConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Storing configuration in Vault")

	// Store main configuration
	configData := map[string]string{
		"domain":         config.Domain,
		"admin_email":    config.AdminEmail,
		"enable_auth":    fmt.Sprintf("%v", config.EnableAuth),
		"enable_metrics": fmt.Sprintf("%v", config.EnableMetrics),
	}

	if config.DNSProvider != "" {
		configData["dns_provider"] = config.DNSProvider
	}

	// Use eos_cli to store in Vault
	for key, value := range configData {
		path := fmt.Sprintf("secret/hecate/config/%s", key)
		if err := storeVaultSecret(rc, path, value); err != nil {
			return fmt.Errorf("failed to store %s: %w", key, err)
		}
	}

	// Store DNS API token separately
	if config.DNSAPIToken != "" {
		if err := storeVaultSecret(rc, "secret/hecate/dns/api_token", config.DNSAPIToken); err != nil {
			return fmt.Errorf("failed to store DNS API token: %w", err)
		}
	}

	return nil
}

// storeVaultSecret is a helper to store a single secret in Vault
func storeVaultSecret(rc *eos_io.RuntimeContext, path, value string) error {
	// This would use eos_cli.ExecCommand to run vault kv put
	// Implementation depends on the eos_cli package
	return nil
}

// provideManualInstructions displays manual deployment instructions
func provideManualInstructions(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Manual Hecate Deployment Instructions")
	logger.Info("terminal prompt: =====================================")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 1. Prerequisites:")
	logger.Info("terminal prompt:    - Nomad cluster running")
	logger.Info("terminal prompt:    - Consul for service discovery")
	logger.Info("terminal prompt:    - Vault for secrets management")
	logger.Info("terminal prompt:    - Docker for containerization")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 2. Deploy PostgreSQL:")
	logger.Info("terminal prompt:    nomad job run /opt/eos//states/hecate/files/nomad/postgres.nomad")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 3. Deploy Redis:")
	logger.Info("terminal prompt:    nomad job run /opt/eos//states/hecate/files/nomad/redis.nomad")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 4. Deploy Authentik:")
	logger.Info("terminal prompt:    nomad job run /opt/eos//states/hecate/files/nomad/authentik-server.nomad")
	logger.Info("terminal prompt:    nomad job run /opt/eos//states/hecate/files/nomad/authentik-worker.nomad")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 5. Deploy Caddy:")
	logger.Info("terminal prompt:    nomad job run /opt/eos//states/hecate/files/nomad/caddy.nomad")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: 6. Configure routes in /opt/hecate/caddy/routes/")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: For automated deployment, use: eos create hecate")

	return nil
}
