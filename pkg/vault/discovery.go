// pkg/vault/discovery.go
// Vault service discovery via Consul

package vault

import (
	"context"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultDiscovery handles discovering Vault instances via Consul
type VaultDiscovery struct {
	consulClient *api.Client
	environment  string
	logger       otelzap.LoggerWithCtx
}

// NewVaultDiscovery creates a new Vault discovery client
func NewVaultDiscovery(rc *eos_io.RuntimeContext, environment string) (*VaultDiscovery, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Connect to Consul
	config := api.DefaultConfig()
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	return &VaultDiscovery{
		consulClient: client,
		environment:  environment,
		logger:       logger,
	}, nil
}

// DiscoverVaultAddress discovers the Vault address for the current environment
// This is the SINGLE SOURCE OF TRUTH for Vault location
func (vd *VaultDiscovery) DiscoverVaultAddress(ctx context.Context) (string, error) {
	logger := vd.logger

	// ASSESS - Try multiple discovery methods in order of preference

	// Method 1: Environment variable (highest priority for manual override)
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		logger.Debug("Using Vault address from VAULT_ADDR environment variable",
			zap.String("address", addr))
		return addr, nil
	}

	// Method 2: Consul service discovery (preferred for production)
	logger.Debug("Discovering Vault via Consul service catalog",
		zap.String("environment", vd.environment))

	services, _, err := vd.consulClient.Health().Service("vault", "active", true, &api.QueryOptions{
		Datacenter: vd.environment,
	})

	if err == nil && len(services) > 0 {
		service := services[0]
		addr := fmt.Sprintf("https://%s:%d", service.Service.Address, service.Service.Port)
		logger.Info("Discovered Vault via Consul service discovery",
			zap.String("address", addr),
			zap.String("environment", vd.environment))
		return addr, nil
	}

	// Method 3: Consul K/V store (fallback)
	logger.Debug("Trying Consul K/V for Vault address")
	kvKey := fmt.Sprintf("eos/config/%s/vault_address", vd.environment)
	pair, _, err := vd.consulClient.KV().Get(kvKey, &api.QueryOptions{
		Datacenter: vd.environment,
	})

	if err == nil && pair != nil {
		addr := string(pair.Value)
		logger.Info("Discovered Vault via Consul K/V",
			zap.String("address", addr),
			zap.String("key", kvKey))
		return addr, nil
	}

	// Method 4: DNS (simplest, but requires DNS resolution configured)
	dnsAddr := fmt.Sprintf("https://vault.service.%s.consul:8200", vd.environment)
	logger.Debug("Attempting Vault discovery via DNS",
		zap.String("address", dnsAddr))

	// Return DNS address as last resort
	// Note: This will fail if Consul DNS is not configured, but that's okay
	// User will get clear error message
	return dnsAddr, nil
}

// RegisterVault registers a Vault instance with Consul
// This is idempotent - safe to call multiple times
func (vd *VaultDiscovery) RegisterVault(ctx context.Context, config VaultRegistration) error {
	logger := vd.logger

	// ASSESS - Check if already registered
	services, err := vd.consulClient.Agent().Services()
	if err != nil {
		return fmt.Errorf("failed to query existing services: %w", err)
	}

	serviceID := fmt.Sprintf("vault-%s", config.NodeName)
	if existing, exists := services[serviceID]; exists {
		logger.Info("Vault already registered, checking if update needed",
			zap.String("service_id", serviceID))

		// Idempotent: Check if config changed
		if existing.Port == config.Port && existing.Address == config.Address {
			logger.Info("Vault already registered with correct configuration")
			return nil
		}
	}

	// INTERVENE - Register or update Vault service
	registration := &api.AgentServiceRegistration{
		ID:      serviceID,
		Name:    "vault",
		Address: config.Address,
		Port:    config.Port,
		Tags:    config.Tags,
		Meta: map[string]string{
			"version":     config.Version,
			"datacenter":  vd.environment,
			"environment": vd.environment,
			"managed_by":  "eos",
		},
		Check: &api.AgentServiceCheck{
			HTTP:                           fmt.Sprintf("https://%s:%d/v1/sys/health", config.Address, config.Port),
			Interval:                       "10s",
			Timeout:                        "2s",
			TLSSkipVerify:                  config.TLSSkipVerify,
			DeregisterCriticalServiceAfter: "1m",
		},
	}

	if err := vd.consulClient.Agent().ServiceRegister(registration); err != nil {
		return fmt.Errorf("failed to register Vault service: %w", err)
	}

	// Also store in K/V for fallback
	vaultAddr := fmt.Sprintf("https://%s:%d", config.Address, config.Port)
	kvKey := fmt.Sprintf("eos/config/%s/vault_address", vd.environment)
	pair := &api.KVPair{
		Key:   kvKey,
		Value: []byte(vaultAddr),
	}

	if _, err := vd.consulClient.KV().Put(pair, &api.WriteOptions{
		Datacenter: vd.environment,
	}); err != nil {
		logger.Warn("Failed to store Vault address in K/V (non-critical)",
			zap.Error(err))
	}

	logger.Info("Vault registered with Consul",
		zap.String("service_id", serviceID),
		zap.String("address", vaultAddr),
		zap.String("environment", vd.environment))

	return nil
}

// VaultRegistration contains Vault registration parameters
type VaultRegistration struct {
	NodeName      string
	Address       string
	Port          int
	Version       string
	Tags          []string
	TLSSkipVerify bool
}

// DetectEnvironment detects which environment we're running in
// Priority: CLI flag > Consul K/V > Hostname detection > default
func DetectEnvironment(ctx context.Context) string {
	// Try Consul K/V first
	client, err := api.NewClient(api.DefaultConfig())
	if err == nil {
		pair, _, err := client.KV().Get("eos/config/current_environment", nil)
		if err == nil && pair != nil {
			return string(pair.Value)
		}
	}

	// Try hostname detection
	hostname, err := os.Hostname()
	if err == nil {
		if contains(hostname, "dev") {
			return "dev"
		}
		if contains(hostname, "staging") || contains(hostname, "sh") {
			return "staging"
		}
		if contains(hostname, "prod") || contains(hostname, "net") {
			return "production"
		}
	}

	// Default to production (safe choice)
	return "production"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && s[len(s)-len(substr):] == substr
}
