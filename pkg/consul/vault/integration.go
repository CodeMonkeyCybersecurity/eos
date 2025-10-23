// pkg/consul/vault/integration.go
//
// Comprehensive Vault-Consul integration with ACL token lifecycle management
// Replaces file-based service registration with SDK-based approach
//
// Last Updated: 2025-10-23

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/acl"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/registry"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultIntegration manages Vault-Consul integration
type VaultIntegration struct {
	rc            *eos_io.RuntimeContext
	logger        otelzap.LoggerWithCtx
	registry      registry.ServiceRegistry
	policyManager acl.PolicyManager
	tokenManager  acl.TokenManager
	consulAddress string
	vaultAddress  string
}

// IntegrationConfig configures Vault-Consul integration
type IntegrationConfig struct {
	ConsulAddress    string        // Consul API address
	ConsulACLToken   string        // Consul management token for ACL operations
	VaultAddress     string        // Vault API address
	ServiceID        string        // Custom service ID (default: vault-<hostname>)
	AutoCreatePolicy bool          // Automatically create Vault ACL policy
	AutoCreateToken  bool          // Automatically create ACL token for Vault
	TokenTTL         time.Duration // ACL token expiration TTL
}

// NewVaultIntegration creates a new Vault-Consul integration manager
func NewVaultIntegration(rc *eos_io.RuntimeContext, config *IntegrationConfig) (*VaultIntegration, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Validate configuration
	logger.Info("ASSESS: Creating Vault-Consul integration",
		zap.String("consul_address", config.ConsulAddress),
		zap.String("vault_address", config.VaultAddress))

	if config.ConsulAddress == "" {
		config.ConsulAddress = "127.0.0.1:8500"
	}

	if config.VaultAddress == "" {
		// Use unified address resolution (env var or smart fallback)
		config.VaultAddress = shared.GetVaultAddrWithEnv()
	}

	// INTERVENE - Create managers
	reg, err := registry.NewServiceRegistry(rc.Ctx, config.ConsulAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create service registry: %w", err)
	}

	var pm acl.PolicyManager
	var tm acl.TokenManager

	if config.AutoCreatePolicy || config.AutoCreateToken {
		if config.ConsulACLToken == "" {
			return nil, fmt.Errorf("consul ACL token required for policy/token creation")
		}

		pm, err = acl.NewPolicyManager(rc.Ctx, config.ConsulAddress, config.ConsulACLToken)
		if err != nil {
			logger.Warn("Failed to create policy manager - ACLs may be disabled",
				zap.Error(err))
		}

		tm, err = acl.NewTokenManager(rc.Ctx, config.ConsulAddress, config.ConsulACLToken)
		if err != nil {
			logger.Warn("Failed to create token manager - ACLs may be disabled",
				zap.Error(err))
		}
	}

	integration := &VaultIntegration{
		rc:            rc,
		logger:        logger,
		registry:      reg,
		policyManager: pm,
		tokenManager:  tm,
		consulAddress: config.ConsulAddress,
		vaultAddress:  config.VaultAddress,
	}

	logger.Info("EVALUATE SUCCESS: Vault-Consul integration created")

	return integration, nil
}

// RegisterVault registers Vault as a service in Consul with ACL policy and token
func (vi *VaultIntegration) RegisterVault(ctx context.Context, config *IntegrationConfig) (*VaultRegistrationResult, error) {
	vi.logger.Info("ASSESS: Registering Vault with Consul")

	result := &VaultRegistrationResult{}

	// Step 1: Create ACL policy (if enabled)
	if config.AutoCreatePolicy && vi.policyManager != nil {
		policy, err := vi.createVaultPolicy(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault ACL policy: %w", err)
		}
		result.PolicyID = policy.ID
		result.PolicyName = policy.Name
		vi.logger.Info("Created Vault ACL policy",
			zap.String("policy_id", policy.ID),
			zap.String("policy_name", policy.Name))
	}

	// Step 2: Create ACL token (if enabled)
	if config.AutoCreateToken && vi.tokenManager != nil && result.PolicyID != "" {
		token, err := vi.createVaultToken(ctx, result.PolicyID, config.TokenTTL)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault ACL token: %w", err)
		}
		result.TokenAccessorID = token.AccessorID
		result.TokenSecretID = token.SecretID
		vi.logger.Info("Created Vault ACL token",
			zap.String("accessor_id", token.AccessorID),
			zap.Duration("ttl", config.TokenTTL))
	}

	// Step 3: Register service
	serviceID := config.ServiceID
	if serviceID == "" {
		hostname := eos_unix.GetInternalHostname()
		serviceID = fmt.Sprintf("vault-%s", hostname)
	}

	service, err := vi.buildServiceRegistration(serviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to build service registration: %w", err)
	}

	if err := vi.registry.RegisterService(ctx, service); err != nil {
		return nil, fmt.Errorf("failed to register Vault service: %w", err)
	}

	result.ServiceID = serviceID
	vi.logger.Info("EVALUATE SUCCESS: Vault registered with Consul",
		zap.String("service_id", serviceID))

	return result, nil
}

// createVaultPolicy creates the Vault access ACL policy
func (vi *VaultIntegration) createVaultPolicy(ctx context.Context) (*acl.Policy, error) {
	vi.logger.Info("Creating Vault access policy")

	// Check if policy already exists
	existing, err := vi.policyManager.ReadPolicyByName(ctx, "vault-access")
	if err == nil && existing != nil {
		vi.logger.Info("Vault access policy already exists, reusing",
			zap.String("policy_id", existing.ID))
		return existing, nil
	}

	// Create new policy
	policy := acl.BuildVaultAccessPolicy()
	created, err := vi.policyManager.CreatePolicy(ctx, policy)
	if err != nil {
		return nil, err
	}

	return created, nil
}

// createVaultToken creates an ACL token for Vault
func (vi *VaultIntegration) createVaultToken(ctx context.Context, policyID string, ttl time.Duration) (*acl.Token, error) {
	vi.logger.Info("Creating Vault ACL token",
		zap.String("policy_id", policyID),
		zap.Duration("ttl", ttl))

	token := &acl.Token{
		Description: "Vault server ACL token (Eos managed)",
		Policies:    []string{policyID},
		Local:       false, // Replicate across datacenters
	}

	if ttl > 0 {
		token.ExpirationTTL = ttl
	}

	created, err := vi.tokenManager.CreateToken(ctx, token)
	if err != nil {
		return nil, err
	}

	return created, nil
}

// buildServiceRegistration builds the Vault service registration
func (vi *VaultIntegration) buildServiceRegistration(serviceID string) (*registry.ServiceRegistration, error) {
	// Detect Vault version
	version, err := vi.getVaultVersion()
	if err != nil {
		vi.logger.Warn("Failed to detect Vault version, using 'unknown'",
			zap.Error(err))
		version = "unknown"
	}

	// Detect storage backend
	storageBackend, err := vi.getVaultStorageBackend()
	if err != nil {
		vi.logger.Warn("Failed to detect Vault storage backend, using 'unknown'",
			zap.Error(err))
		storageBackend = "unknown"
	}

	// Extract host and port from VAULT_ADDR
	host, port, err := vi.parseVaultAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to parse Vault address: %w", err)
	}

	hostname := eos_unix.GetInternalHostname()

	service := &registry.ServiceRegistration{
		ID:      serviceID,
		Name:    "vault",
		Address: host,
		Port:    port,
		Tags: []string{
			"active",
			"tls",
			fmt.Sprintf("storage-%s", storageBackend),
			"primary",
			"eos-managed",
			fmt.Sprintf("version-%s", version),
		},
		Meta: map[string]string{
			"version":      version,
			"storage_type": storageBackend,
			"instance":     hostname,
			"environment":  "production",
			"eos_managed":  "true",
		},
		Check: &registry.HealthCheck{
			ID:                     "vault-health",
			Name:                   "Vault HTTPS Health",
			Type:                   registry.HealthCheckHTTPS,
			HTTP:                   fmt.Sprintf("%s/v1/sys/health?standbyok=true&perfstandbyok=true", vi.vaultAddress),
			Interval:               10 * time.Second,
			Timeout:                5 * time.Second,
			TLSSkipVerify:          true,
			SuccessBeforePassing:   2,
			FailuresBeforeCritical: 3,
		},
		Weights: &registry.ServiceWeights{
			Passing: 10,
			Warning: 1,
		},
	}

	return service, nil
}

// getVaultVersion detects the Vault version
func (vi *VaultIntegration) getVaultVersion() (string, error) {
	cmd := exec.Command("vault", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Parse "Vault v1.15.0 (xyz)" format
	versionLine := strings.TrimSpace(string(output))
	parts := strings.Fields(versionLine)
	if len(parts) < 2 {
		return "unknown", nil
	}

	version := strings.TrimPrefix(parts[1], "v")
	return version, nil
}

// getVaultStorageBackend detects the Vault storage backend type
func (vi *VaultIntegration) getVaultStorageBackend() (string, error) {
	// Try to read from Vault config
	// This is a simplified detection - in production you'd query Vault API
	configPaths := []string{
		"/etc/vault.d/vault.hcl",
		"/etc/vault/vault.hcl",
	}

	for _, path := range configPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		config := string(data)
		if strings.Contains(config, `storage "consul"`) {
			return "consul", nil
		} else if strings.Contains(config, `storage "file"`) {
			return "file", nil
		} else if strings.Contains(config, `storage "raft"`) {
			return "raft", nil
		}
	}

	return "unknown", nil
}

// parseVaultAddress extracts host and port from VAULT_ADDR
func (vi *VaultIntegration) parseVaultAddress() (string, int, error) {
	addr := vi.vaultAddress

	// Remove protocol
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")

	// Split host:port
	parts := strings.Split(addr, ":")
	if len(parts) < 1 {
		return "", 0, fmt.Errorf("invalid vault address: %s", vi.vaultAddress)
	}

	host := parts[0]
	port := 8200 // Default Vault port

	if len(parts) > 1 {
		portStr := parts[1]
		// Remove path if present (e.g., "8200/v1/sys/health")
		if idx := strings.Index(portStr, "/"); idx != -1 {
			portStr = portStr[:idx]
		}
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			vi.logger.Warn("Failed to parse port, using default",
				zap.String("port_str", portStr),
				zap.Error(err))
		}
	}

	return host, port, nil
}

// DeregisterVault removes Vault service registration and optionally cleans up ACL resources
func (vi *VaultIntegration) DeregisterVault(ctx context.Context, serviceID string, cleanupACL bool) error {
	vi.logger.Info("ASSESS: Deregistering Vault from Consul",
		zap.String("service_id", serviceID),
		zap.Bool("cleanup_acl", cleanupACL))

	// Deregister service
	if err := vi.registry.DeregisterService(ctx, serviceID); err != nil {
		return fmt.Errorf("failed to deregister service: %w", err)
	}

	// Cleanup ACL resources if requested
	if cleanupACL && vi.policyManager != nil {
		policy, err := vi.policyManager.ReadPolicyByName(ctx, "vault-access")
		if err == nil && policy != nil {
			if err := vi.policyManager.DeletePolicy(ctx, policy.ID); err != nil {
				vi.logger.Warn("Failed to delete Vault ACL policy",
					zap.String("policy_id", policy.ID),
					zap.Error(err))
			} else {
				vi.logger.Info("Deleted Vault ACL policy",
					zap.String("policy_id", policy.ID))
			}
		}
	}

	vi.logger.Info("EVALUATE SUCCESS: Vault deregistered from Consul")
	return nil
}

// VaultRegistrationResult contains the results of Vault registration
type VaultRegistrationResult struct {
	ServiceID       string // Consul service ID
	PolicyID        string // ACL policy ID (if created)
	PolicyName      string // ACL policy name
	TokenAccessorID string // ACL token accessor ID (if created)
	TokenSecretID   string // ACL token secret ID (THE ACTUAL TOKEN)
}

// GetConsulToken returns the Consul token configuration for Vault
func (result *VaultRegistrationResult) GetConsulToken() string {
	return result.TokenSecretID
}

// GetVaultStorageConfig generates Vault storage configuration using the token
func (result *VaultRegistrationResult) GetVaultStorageConfig(consulAddress string) string {
	if consulAddress == "" {
		consulAddress = "127.0.0.1:8500"
	}

	if result.TokenSecretID == "" {
		// No ACL token - return config without token
		return fmt.Sprintf(`
storage "consul" {
  address = "%s"
  path    = "vault/"
}
`, consulAddress)
	}

	return fmt.Sprintf(`
storage "consul" {
  address = "%s"
  path    = "vault/"
  token   = "%s"
}
`, consulAddress, result.TokenSecretID)
}
