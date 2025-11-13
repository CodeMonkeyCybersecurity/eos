package hecate

import (
	"fmt"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DNSChallengeProvider represents a DNS provider for ACME DNS challenges
type DNSChallengeProvider string

const (
	DNSProviderCloudflare   DNSChallengeProvider = "cloudflare"
	DNSProviderRoute53      DNSChallengeProvider = "route53"
	DNSProviderHetzner      DNSChallengeProvider = "hetzner"
	DNSProviderDigitalOcean DNSChallengeProvider = "digitalocean"
	DNSProviderGoogleCloud  DNSChallengeProvider = "googleclouddns"
	DNSProviderAzure        DNSChallengeProvider = "azuredns"
)

// DNSChallengeConfig holds configuration for DNS challenge
type DNSChallengeConfig struct {
	Provider    DNSChallengeProvider
	Credentials map[string]string
	Domains     []string
}

// GetDNSChallengeConfig generates Caddy configuration for DNS challenge
func GetDNSChallengeConfig(rc *eos_io.RuntimeContext, config *DNSChallengeConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Generating DNS challenge configuration",
		zap.String("provider", string(config.Provider)),
		zap.Strings("domains", config.Domains))

	// Validate provider
	if !isValidProvider(config.Provider) {
		return "", fmt.Errorf("unsupported DNS provider: %s", config.Provider)
	}

	// Generate provider-specific configuration
	providerConfig, err := generateProviderConfig(config)
	if err != nil {
		return "", fmt.Errorf("failed to generate provider config: %w", err)
	}

	// Generate Caddy JSON configuration
	caddyConfig := fmt.Sprintf(`{
  "apps": {
    "tls": {
      "automation": {
        "policies": [{
          "subjects": %s,
          "issuers": [{
            "module": "acme",
            "challenges": {
              "dns": {
                "provider": %s
              }
            }
          }]
        }]
      }
    }
  }
}`, formatDomains(config.Domains), providerConfig)

	return caddyConfig, nil
}

// generateProviderConfig generates provider-specific configuration
func generateProviderConfig(config *DNSChallengeConfig) (string, error) {
	switch config.Provider {
	case DNSProviderCloudflare:
		token, ok := config.Credentials["api_token"]
		if !ok {
			return "", fmt.Errorf("missing api_token for Cloudflare")
		}
		return fmt.Sprintf(`{
          "name": "cloudflare",
          "api_token": "%s"
        }`, token), nil

	case DNSProviderRoute53:
		accessKey, ok1 := config.Credentials["access_key_id"]
		secretKey, ok2 := config.Credentials["secret_access_key"]
		if !ok1 || !ok2 {
			return "", fmt.Errorf("missing AWS credentials for Route53")
		}
		return fmt.Sprintf(`{
          "name": "route53",
          "access_key_id": "%s",
          "secret_access_key": "%s"
        }`, accessKey, secretKey), nil

	case DNSProviderHetzner:
		token, ok := config.Credentials["api_token"]
		if !ok {
			return "", fmt.Errorf("missing api_token for Hetzner")
		}
		return fmt.Sprintf(`{
          "name": "hetzner",
          "api_token": "%s"
        }`, token), nil

	case DNSProviderDigitalOcean:
		token, ok := config.Credentials["auth_token"]
		if !ok {
			return "", fmt.Errorf("missing auth_token for DigitalOcean")
		}
		return fmt.Sprintf(`{
          "name": "digitalocean",
          "auth_token": "%s"
        }`, token), nil

	case DNSProviderGoogleCloud:
		project, ok := config.Credentials["gcp_project"]
		if !ok {
			return "", fmt.Errorf("missing gcp_project for Google Cloud DNS")
		}
		return fmt.Sprintf(`{
          "name": "googleclouddns",
          "gcp_project": "%s"
        }`, project), nil

	case DNSProviderAzure:
		tenantID, ok1 := config.Credentials["tenant_id"]
		clientID, ok2 := config.Credentials["client_id"]
		clientSecret, ok3 := config.Credentials["client_secret"]
		subscriptionID, ok4 := config.Credentials["subscription_id"]
		resourceGroup, ok5 := config.Credentials["resource_group_name"]

		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
			return "", fmt.Errorf("missing Azure credentials")
		}

		return fmt.Sprintf(`{
          "name": "azuredns",
          "tenant_id": "%s",
          "client_id": "%s",
          "client_secret": "%s",
          "subscription_id": "%s",
          "resource_group_name": "%s"
        }`, tenantID, clientID, clientSecret, subscriptionID, resourceGroup), nil

	default:
		return "", fmt.Errorf("unsupported provider: %s", config.Provider)
	}
}

// ConfigureDNSChallenge configures Caddy to use DNS challenge
func ConfigureDNSChallenge(rc *eos_io.RuntimeContext, provider DNSChallengeProvider, domains []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring DNS challenge for Caddy",
		zap.String("provider", string(provider)),
		zap.Strings("domains", domains))

	// Get secret manager
	secretManager, err := NewSecretManager(rc)
	if err != nil {
		return fmt.Errorf("failed to initialize secret manager: %w", err)
	}

	// Retrieve provider credentials from secrets
	credentials := make(map[string]string)

	switch provider {
	case DNSProviderCloudflare:
		token, err := secretManager.GetSecret("dns", "cloudflare_api_token")
		if err != nil {
			return fmt.Errorf("failed to get Cloudflare API token: %w", err)
		}
		credentials["api_token"] = token

	case DNSProviderHetzner:
		token, err := secretManager.GetSecret("dns", "hetzner_api_token")
		if err != nil {
			return fmt.Errorf("failed to get Hetzner API token: %w", err)
		}
		credentials["api_token"] = token

	// Add other providers as needed
	default:
		return fmt.Errorf("provider %s not yet implemented", provider)
	}

	// Create DNS challenge configuration
	config := &DNSChallengeConfig{
		Provider:    provider,
		Credentials: credentials,
		Domains:     domains,
	}

	// Generate Caddy configuration
	caddyConfig, err := GetDNSChallengeConfig(rc, config)
	if err != nil {
		return fmt.Errorf("failed to generate DNS challenge config: %w", err)
	}

	// Apply configuration to Caddy
	if err := applyCaddyConfig(rc, caddyConfig); err != nil {
		return fmt.Errorf("failed to apply Caddy config: %w", err)
	}

	logger.Info("DNS challenge configured successfully")
	return nil
}

// Helper functions

func isValidProvider(provider DNSChallengeProvider) bool {
	validProviders := []DNSChallengeProvider{
		DNSProviderCloudflare,
		DNSProviderRoute53,
		DNSProviderHetzner,
		DNSProviderDigitalOcean,
		DNSProviderGoogleCloud,
		DNSProviderAzure,
	}

	for _, valid := range validProviders {
		if provider == valid {
			return true
		}
	}
	return false
}

func formatDomains(domains []string) string {
	quotedDomains := make([]string, len(domains))
	for i, domain := range domains {
		quotedDomains[i] = fmt.Sprintf(`"%s"`, domain)
	}
	return "[" + strings.Join(quotedDomains, ", ") + "]"
}

func applyCaddyConfig(rc *eos_io.RuntimeContext, config string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug("Applying Caddy configuration")

	// TODO: Implement actual Caddy API call
	// This would POST to http://localhost:2019/load

	return nil
}
