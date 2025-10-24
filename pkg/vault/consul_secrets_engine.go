// pkg/vault/consul_secrets_engine.go
//
// Vault Consul Secrets Engine Integration
//
// This module enables Vault to generate dynamic Consul ACL tokens for applications.
// It implements the recommended pattern where:
// - Vault uses Raft storage (self-contained, no Consul dependency)
// - Consul is used for service discovery and configuration (KV store)
// - Vault generates short-lived Consul tokens dynamically (via secrets engine)
//
// This eliminates the circular dependency of "Consul storage backend" while
// still enabling Vault→Consul integration for token management.
//
// Reference: https://developer.hashicorp.com/vault/docs/secrets/consul

package vault

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulSecretsEngineConfig configures the Vault Consul secrets engine
type ConsulSecretsEngineConfig struct {
	// Consul connection
	ConsulAddress string // Consul agent address (e.g., "127.0.0.1:8500")
	ConsulScheme  string // http or https
	ConsulToken   string // Management token for Vault to manage Consul ACLs

	// Vault roles to create
	Roles []ConsulRole

	// TTL settings
	DefaultTTL string // Default token TTL (e.g., "1h")
	MaxTTL     string // Maximum token TTL (e.g., "24h")
}

// ConsulRole defines a Vault role for Consul token generation
type ConsulRole struct {
	Name     string   // Role name (e.g., "eos-role", "service-role")
	Policies []string // Consul ACL policies to attach (e.g., ["eos-policy"])
	TTL      string   // Token TTL for this role (e.g., "1h")
	MaxTTL   string   // Maximum token TTL (e.g., "24h")
}

// ConsulSecretsEngineManager handles Vault Consul secrets engine operations
type ConsulSecretsEngineManager struct {
	rc           *eos_io.RuntimeContext
	vaultClient  *vaultapi.Client
	consulClient *consulapi.Client
	logger       otelzap.LoggerWithCtx
}

// NewConsulSecretsEngineManager creates a new manager instance
func NewConsulSecretsEngineManager(rc *eos_io.RuntimeContext, vaultClient *vaultapi.Client, consulClient *consulapi.Client) *ConsulSecretsEngineManager {
	return &ConsulSecretsEngineManager{
		rc:           rc,
		vaultClient:  vaultClient,
		consulClient: consulClient,
		logger:       otelzap.Ctx(rc.Ctx),
	}
}

// EnableConsulSecretsEngine enables and configures the Consul secrets engine in Vault
func (m *ConsulSecretsEngineManager) EnableConsulSecretsEngine(config *ConsulSecretsEngineConfig) error {
	m.logger.Info("Enabling Vault Consul secrets engine",
		zap.String("consul_address", config.ConsulAddress),
		zap.Int("roles_count", len(config.Roles)))

	// ASSESS - Check if Consul secrets engine is already enabled
	mounts, err := m.vaultClient.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list Vault mounts: %w", err)
	}

	if _, exists := mounts["consul/"]; exists {
		m.logger.Info("Consul secrets engine already enabled",
			zap.String("path", "consul/"))
	} else {
		// INTERVENE - Enable Consul secrets engine
		m.logger.Info("Enabling Consul secrets engine")

		mountInput := &vaultapi.MountInput{
			Type:        "consul",
			Description: "Dynamic Consul ACL token generation",
			Config: vaultapi.MountConfigInput{
				DefaultLeaseTTL: config.DefaultTTL,
				MaxLeaseTTL:     config.MaxTTL,
			},
		}

		if err := m.vaultClient.Sys().Mount("consul", mountInput); err != nil {
			return fmt.Errorf("failed to enable Consul secrets engine: %w", err)
		}

		m.logger.Info("Consul secrets engine enabled successfully")
	}

	// INTERVENE - Configure Consul connection
	m.logger.Info("Configuring Vault→Consul connection")

	configData := map[string]interface{}{
		"address": config.ConsulAddress,
		"scheme":  config.ConsulScheme,
		"token":   config.ConsulToken,
	}

	if _, err := m.vaultClient.Logical().Write("consul/config/access", configData); err != nil {
		return fmt.Errorf("failed to configure Consul connection: %w", err)
	}

	m.logger.Info("Consul connection configured")

	// INTERVENE - Create roles
	for _, role := range config.Roles {
		if err := m.createRole(role); err != nil {
			m.logger.Warn("Failed to create Consul role",
				zap.String("role", role.Name),
				zap.Error(err))
			// Continue with other roles
		}
	}

	// EVALUATE - Verify configuration
	if err := m.verifyConfiguration(); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	m.logger.Info("Consul secrets engine configuration complete",
		zap.Int("roles_created", len(config.Roles)))

	return nil
}

// createRole creates a Vault role for Consul token generation
func (m *ConsulSecretsEngineManager) createRole(role ConsulRole) error {
	m.logger.Info("Creating Consul role",
		zap.String("role", role.Name),
		zap.Strings("policies", role.Policies))

	roleData := map[string]interface{}{
		"policies": role.Policies,
		"ttl":      role.TTL,
		"max_ttl":  role.MaxTTL,
	}

	path := fmt.Sprintf("consul/roles/%s", role.Name)
	if _, err := m.vaultClient.Logical().Write(path, roleData); err != nil {
		return fmt.Errorf("failed to create role %s: %w", role.Name, err)
	}

	m.logger.Info("Consul role created",
		zap.String("role", role.Name),
		zap.String("path", path))

	return nil
}

// verifyConfiguration verifies the Consul secrets engine is working
func (m *ConsulSecretsEngineManager) verifyConfiguration() error {
	m.logger.Info("Verifying Consul secrets engine configuration")

	// Read the config to ensure it's set
	config, err := m.vaultClient.Logical().Read("consul/config/access")
	if err != nil {
		return fmt.Errorf("failed to read Consul config: %w", err)
	}

	if config == nil {
		return fmt.Errorf("Consul config not found - configuration may have failed")
	}

	m.logger.Info("Consul secrets engine verification successful",
		zap.String("consul_address", config.Data["address"].(string)))

	return nil
}

// TestTokenGeneration tests generating a Consul token from a Vault role
func (m *ConsulSecretsEngineManager) TestTokenGeneration(roleName string) (*ConsulTokenInfo, error) {
	m.logger.Info("Testing Consul token generation",
		zap.String("role", roleName))

	path := fmt.Sprintf("consul/creds/%s", roleName)
	secret, err := m.vaultClient.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Consul token: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("no token returned from Vault")
	}

	token, ok := secret.Data["token"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid token format in response")
	}

	accessor, _ := secret.Data["accessor"].(string)

	tokenInfo := &ConsulTokenInfo{
		Token:     token,
		Accessor:  accessor,
		LeaseDuration: time.Duration(secret.LeaseDuration) * time.Second,
		Renewable: secret.Renewable,
	}

	m.logger.Info("Consul token generated successfully",
		zap.String("role", roleName),
		zap.String("accessor", accessor),
		zap.Duration("ttl", tokenInfo.LeaseDuration))

	return tokenInfo, nil
}

// ConsulTokenInfo contains information about a generated Consul token
type ConsulTokenInfo struct {
	Token         string        // The Consul ACL token
	Accessor      string        // Token accessor for revocation
	LeaseDuration time.Duration // Token TTL
	Renewable     bool          // Whether token can be renewed
}

// CreateDefaultRoles creates standard EOS Consul roles
func CreateDefaultConsulRoles() []ConsulRole {
	return []ConsulRole{
		{
			Name:     "eos-role",
			Policies: []string{"eos-policy"},
			TTL:      "1h",
			MaxTTL:   "24h",
		},
		{
			Name:     "service-role",
			Policies: []string{"service-policy"},
			TTL:      "2h",
			MaxTTL:   "48h",
		},
		{
			Name:     "readonly-role",
			Policies: []string{"readonly-policy"},
			TTL:      "8h",
			MaxTTL:   "72h",
		},
	}
}

// DisableConsulSecretsEngine disables the Consul secrets engine
func (m *ConsulSecretsEngineManager) DisableConsulSecretsEngine() error {
	m.logger.Info("Disabling Consul secrets engine")

	if err := m.vaultClient.Sys().Unmount("consul"); err != nil {
		return fmt.Errorf("failed to disable Consul secrets engine: %w", err)
	}

	m.logger.Info("Consul secrets engine disabled")
	return nil
}
