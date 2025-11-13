// pkg/hecate/consul_config.go
// Consul-backed configuration storage for Hecate

package hecate

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

const (
	// Consul KV paths for Hecate configuration
	ConsulHecatePrefix       = "hecate/"
	ConsulConfigDomain       = ConsulHecatePrefix + "config/domain"
	ConsulConfigServerIP     = ConsulHecatePrefix + "config/server_ip"
	ConsulConfigDNSToken     = ConsulHecatePrefix + "config/hetzner_dns_token"
	ConsulConfigVaultEnabled = ConsulHecatePrefix + "config/vault_enabled"
)

// HecateConsulConfig holds Hecate configuration that can be stored in Consul
type HecateConsulConfig struct {
	Domain          string
	ServerIP        string
	HetznerDNSToken string
	VaultEnabled    bool
	ConsulAvailable bool
}

// ConsulConfigManager handles reading/writing Hecate config to Consul KV
type ConsulConfigManager struct {
	client *api.Client
	logger *otelzap.LoggerWithCtx
}

// NewConsulConfigManager creates a new Consul config manager
func NewConsulConfigManager(rc *eos_io.RuntimeContext) (*ConsulConfigManager, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get Consul address from environment or use default
	consulAddr := shared.GetConsulAddrWithEnv()

	// Try to connect to Consul
	config := api.DefaultConfig()
	config.Address = consulAddr

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	// Test connection
	_, err = client.Agent().Self()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Consul at %s: %w", consulAddr, err)
	}

	logger.Info("Connected to Consul", zap.String("address", consulAddr))

	return &ConsulConfigManager{
		client: client,
		logger: &logger,
	}, nil
}

// LoadOrPromptConfig loads config from Consul, or prompts user if not found
func (m *ConsulConfigManager) LoadOrPromptConfig(rc *eos_io.RuntimeContext, promptForMissing bool) (*HecateConsulConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	config := &HecateConsulConfig{ConsulAvailable: true}

	// ASSESS - Try to load existing config from Consul
	logger.Info("Checking for existing Hecate configuration in Consul")

	// Load domain
	domain, err := m.getKey(ConsulConfigDomain)
	if err == nil && domain != "" {
		config.Domain = domain
		logger.Info("Loaded domain from Consul", zap.String("domain", domain))
	}

	// Load server IP
	serverIP, err := m.getKey(ConsulConfigServerIP)
	if err == nil && serverIP != "" {
		config.ServerIP = serverIP
		logger.Info("Loaded server IP from Consul", zap.String("ip", serverIP))
	}

	// Load Hetzner DNS token (prefer environment variable, fallback to Consul)
	dnsToken := os.Getenv("HETZNER_DNS_API_TOKEN")
	if dnsToken == "" {
		dnsToken, err = m.getKey(ConsulConfigDNSToken)
		if err == nil && dnsToken != "" {
			config.HetznerDNSToken = dnsToken
			logger.Info("Loaded Hetzner DNS token from Consul")
		}
	} else {
		config.HetznerDNSToken = dnsToken
		logger.Info("Using Hetzner DNS token from environment variable")
	}

	// Check if we have existing config
	hasExistingConfig := config.Domain != ""

	if hasExistingConfig {
		logger.Info("")
		logger.Info("Found existing Hecate configuration:")
		logger.Info("  Domain: " + config.Domain)
		if config.ServerIP != "" {
			logger.Info("  Server IP: " + config.ServerIP)
		}
		if config.HetznerDNSToken != "" {
			logger.Info("  Hetzner DNS: Configured")
		}
		logger.Info("")

		// Ask if user wants to use existing config
		if interaction.PromptYesNo(rc.Ctx, "Use these existing settings?", true) {
			logger.Info("Using existing configuration from Consul")
			return config, nil
		}

		logger.Info("Will prompt for new configuration")
	}

	// INTERVENE - Prompt for missing or new configuration
	if promptForMissing {
		if config.Domain == "" || !hasExistingConfig {
			logger.Info("terminal prompt: Enter your domain (e.g., example.com):")
			domain, err := eos_io.ReadInput(rc)
			if err != nil {
				return nil, fmt.Errorf("failed to read domain: %w", err)
			}
			config.Domain = domain
		}

		// Server IP can be detected automatically, so we don't always need to prompt
	}

	return config, nil
}

// SaveConfig saves Hecate configuration to Consul KV
func (m *ConsulConfigManager) SaveConfig(rc *eos_io.RuntimeContext, config *HecateConsulConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Saving Hecate configuration to Consul")

	// Save domain
	if config.Domain != "" {
		if err := m.setKey(ConsulConfigDomain, config.Domain); err != nil {
			return fmt.Errorf("failed to save domain: %w", err)
		}
		logger.Info("Saved domain to Consul", zap.String("domain", config.Domain))
	}

	// Save server IP
	if config.ServerIP != "" {
		if err := m.setKey(ConsulConfigServerIP, config.ServerIP); err != nil {
			return fmt.Errorf("failed to save server IP: %w", err)
		}
		logger.Info("Saved server IP to Consul", zap.String("ip", config.ServerIP))
	}

	// Save Hetzner DNS token (only if not from environment)
	if config.HetznerDNSToken != "" && os.Getenv("HETZNER_DNS_API_TOKEN") == "" {
		logger.Warn("Storing Hetzner DNS token in Consul (consider using Vault for secrets)")
		if err := m.setKey(ConsulConfigDNSToken, config.HetznerDNSToken); err != nil {
			return fmt.Errorf("failed to save DNS token: %w", err)
		}
		logger.Info("Saved Hetzner DNS token to Consul")
	}

	logger.Info("Configuration saved successfully to Consul")
	return nil
}

// SaveRoute saves a route configuration to Consul
func (m *ConsulConfigManager) SaveRoute(rc *eos_io.RuntimeContext, subdomain, backendIP string, backendPort int) error {
	logger := otelzap.Ctx(rc.Ctx)

	routePrefix := fmt.Sprintf("%sroutes/%s/", ConsulHecatePrefix, subdomain)

	if err := m.setKey(routePrefix+"subdomain", subdomain); err != nil {
		return err
	}
	if err := m.setKey(routePrefix+"backend_ip", backendIP); err != nil {
		return err
	}
	if err := m.setKey(routePrefix+"backend_port", fmt.Sprintf("%d", backendPort)); err != nil {
		return err
	}

	logger.Info("Saved route to Consul",
		zap.String("subdomain", subdomain),
		zap.String("backend_ip", backendIP),
		zap.Int("backend_port", backendPort))

	return nil
}

// GetAllRoutes retrieves all configured routes from Consul
func (m *ConsulConfigManager) GetAllRoutes(rc *eos_io.RuntimeContext) (map[string]map[string]string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	routesPrefix := ConsulHecatePrefix + "routes/"

	// List all keys under routes/
	pairs, _, err := m.client.KV().List(routesPrefix, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	routes := make(map[string]map[string]string)

	for _, pair := range pairs {
		// Parse route name from key path (e.g., "hecate/routes/delphi/backend_ip")
		// Extract "delphi" as subdomain
		key := pair.Key
		if len(key) <= len(routesPrefix) {
			continue
		}

		// Parse subdomain and field
		parts := splitPath(key[len(routesPrefix):])
		if len(parts) < 2 {
			continue
		}

		subdomain := parts[0]
		field := parts[1]

		if routes[subdomain] == nil {
			routes[subdomain] = make(map[string]string)
		}
		routes[subdomain][field] = string(pair.Value)
	}

	logger.Info("Retrieved routes from Consul", zap.Int("count", len(routes)))
	return routes, nil
}

// Helper methods

func (m *ConsulConfigManager) getKey(key string) (string, error) {
	pair, _, err := m.client.KV().Get(key, nil)
	if err != nil {
		return "", err
	}
	if pair == nil {
		return "", fmt.Errorf("key not found: %s", key)
	}
	return string(pair.Value), nil
}

func (m *ConsulConfigManager) setKey(key, value string) error {
	p := &api.KVPair{Key: key, Value: []byte(value)}
	_, err := m.client.KV().Put(p, nil)
	return err
}

func splitPath(path string) []string {
	// Split path by '/' and filter empty strings
	var parts []string
	for _, part := range splitString(path, '/') {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func splitString(s string, sep rune) []string {
	var parts []string
	start := 0
	for i, c := range s {
		if c == sep {
			if i > start {
				parts = append(parts, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}
