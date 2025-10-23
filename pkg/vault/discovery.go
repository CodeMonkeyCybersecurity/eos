// pkg/vault/discovery.go
// Vault service discovery via Consul

package vault

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
	// NOTE: For direct address resolution, use shared.GetVaultAddrWithEnv() instead.
	// This discovery function implements more complex logic (Consul service discovery, etc.)
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
	dnsAddr := fmt.Sprintf("https://vault.service.%s.consul:%d", vd.environment, shared.PortVault)
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

	// CRITICAL: Only store in K/V if environment is set
	// Empty environment causes "404 Unexpected response code" in Consul
	if vd.environment != "" {
		kvKey := fmt.Sprintf("eos/config/%s/vault_address", vd.environment)
		pair := &api.KVPair{
			Key:   kvKey,
			Value: []byte(vaultAddr),
		}

		writeOpts := &api.WriteOptions{}
		if vd.environment != "" {
			writeOpts.Datacenter = vd.environment
		}

		if _, err := vd.consulClient.KV().Put(pair, writeOpts); err != nil {
			logger.Warn("Failed to store Vault address in K/V (non-critical)",
				zap.Error(err),
				zap.String("key", kvKey))
		} else {
			logger.Debug("Stored Vault address in Consul K/V for fallback discovery",
				zap.String("key", kvKey),
				zap.String("address", vaultAddr))
		}
	} else {
		logger.Debug("Skipping Consul K/V storage (no environment specified)",
			zap.String("note", "K/V storage requires environment to be set"))
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

// ValidateVaultAddress validates and normalizes a Vault address
// Accepts: IP addresses, DNS names, Tailscale names (e.g., vhost5)
// Returns: normalized address with protocol and port
func (vd *VaultDiscovery) ValidateVaultAddress(ctx context.Context, address string) (string, error) {
	logger := vd.logger

	// ASSESS - Validate address format
	logger.Debug("Validating Vault address", zap.String("input", address))

	// Sanitize the address
	address = shared.SanitizeURL(address)

	// Parse as URL if it has a scheme
	if strings.HasPrefix(address, "http://") || strings.HasPrefix(address, "https://") {
		parsedURL, err := url.Parse(address)
		if err != nil {
			return "", fmt.Errorf("invalid URL format: %w", err)
		}

		// Ensure https (Vault should always use TLS)
		if parsedURL.Scheme == "http" {
			logger.Warn("Converting http to https for Vault security")
			parsedURL.Scheme = "https"
		}

		// If no port specified, add default Vault port
		if parsedURL.Port() == "" {
			parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), strconv.Itoa(shared.PortVault))
		}

		normalized := parsedURL.String()
		logger.Debug("Normalized URL address", zap.String("normalized", normalized))
		return normalized, nil
	}

	// No scheme provided - treat as hostname or IP
	host := address
	port := shared.PortVault // Default Vault port

	// Check if port is included (e.g., "vhost5:8200" or "192.168.1.10:8200")
	if strings.Contains(address, ":") {
		parts := strings.Split(address, ":")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid address format: %s (expected host:port or just host)", address)
		}
		host = parts[0]
		parsedPort, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", fmt.Errorf("invalid port number: %s", parts[1])
		}
		port = parsedPort
	}

	// Validate host is either IP or valid hostname
	if net.ParseIP(host) == nil {
		// Not an IP, must be a hostname/DNS name
		// Simple validation: no spaces, no special chars except dots and hyphens
		if strings.ContainsAny(host, " !@#$%^&*()+=[]{}|\\;'\"<>?/") {
			return "", fmt.Errorf("invalid hostname: %s (contains invalid characters)", host)
		}
	}

	// Construct final address
	normalized := fmt.Sprintf("https://%s:%d", host, port)
	logger.Info("Validated and normalized Vault address",
		zap.String("input", address),
		zap.String("normalized", normalized))

	return normalized, nil
}

// StoreVaultAddress stores the Vault address in Consul KV
// This becomes the source of truth for Vault discovery (Method 3)
func (vd *VaultDiscovery) StoreVaultAddress(ctx context.Context, address string) error {
	logger := vd.logger

	// ASSESS - Validate address first
	normalizedAddr, err := vd.ValidateVaultAddress(ctx, address)
	if err != nil {
		return fmt.Errorf("invalid Vault address: %w", err)
	}

	// INTERVENE - Store in Consul KV
	kvKey := fmt.Sprintf("eos/config/%s/vault_address", vd.environment)
	pair := &api.KVPair{
		Key:   kvKey,
		Value: []byte(normalizedAddr),
	}

	logger.Debug("Storing Vault address in Consul KV",
		zap.String("key", kvKey),
		zap.String("address", normalizedAddr),
		zap.String("environment", vd.environment))

	if _, err := vd.consulClient.KV().Put(pair, &api.WriteOptions{
		Datacenter: vd.environment,
	}); err != nil {
		return fmt.Errorf("failed to store Vault address in Consul KV: %w", err)
	}

	// EVALUATE - Verify storage
	storedPair, _, err := vd.consulClient.KV().Get(kvKey, &api.QueryOptions{
		Datacenter: vd.environment,
	})
	if err != nil {
		logger.Warn("Failed to verify stored address (non-critical)",
			zap.Error(err))
	} else if storedPair == nil {
		logger.Warn("Stored address not found during verification (possible replication delay)")
	} else if string(storedPair.Value) != normalizedAddr {
		return fmt.Errorf("verification failed: stored value mismatch (expected %s, got %s)",
			normalizedAddr, string(storedPair.Value))
	}

	logger.Info("Vault address stored successfully",
		zap.String("key", kvKey),
		zap.String("address", normalizedAddr),
		zap.String("environment", vd.environment))

	return nil
}
