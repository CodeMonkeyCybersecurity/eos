// pkg/vault/phase9f_consul_secrets.go
//
// Phase 9f: Enable Consul Secrets Engine
//
// This phase enables Vault's Consul secrets engine for dynamic token generation.
// Part of Phase 1 implementation (Vault + Consul integration).

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	consulapi "github.com/hashicorp/consul/api"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PhaseEnableConsulSecretsEngine enables and configures the Consul secrets engine
func PhaseEnableConsulSecretsEngine(rc *eos_io.RuntimeContext, vaultClient *vaultapi.Client) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Consul secrets engine configuration")

	// ASSESS - Check if Consul is available
	logger.Info(" [ASSESS] Checking if Consul is available")

	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = shared.GetConsulHostPort()

	consulClient, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Warn("Failed to create Consul client",
			zap.Error(err),
			zap.String("reason", "Consul may not be installed"))
		return fmt.Errorf("Consul not available: %w", err)
	}

	// Test Consul connection
	_, err = consulClient.Status().Leader()
	if err != nil {
		logger.Warn("Consul is not running or not accessible",
			zap.Error(err),
			zap.String("consul_address", consulConfig.Address))
		return fmt.Errorf("Consul not accessible: %w", err)
	}

	logger.Info(" [ASSESS] Consul is available",
		zap.String("consul_address", consulConfig.Address))

	// ASSESS - Check if we have a Consul management token
	// For now, we'll skip this step if no token is available
	// The operator can configure it manually later with the --consul-token flag
	logger.Info(" [ASSESS] Checking for Consul ACL configuration")

	// Try to read ACL bootstrap status
	_, _, err = consulClient.ACL().Bootstrap()
	if err != nil {
		// Bootstrap already done or ACLs not enabled - this is expected
		logger.Debug("Consul ACL bootstrap status",
			zap.Error(err),
			zap.String("interpretation", "ACLs may be already configured or disabled"))
	}

	// INTERVENE - Enable Consul secrets engine
	logger.Info(" [INTERVENE] Enabling Consul secrets engine")

	// Create configuration with defaults
	// Note: Without a management token, we can only enable the engine
	// The operator must configure it manually with: vault write consul/config/access
	config := &ConsulSecretsEngineConfig{
		ConsulAddress: consulConfig.Address,
		ConsulScheme:  "http",
		ConsulToken:   "",             // Will be configured later by operator
		Roles:         []ConsulRole{}, // Roles will be created after token is configured
		DefaultTTL:    "1h",
		MaxTTL:        "24h",
	}

	// Check if already enabled
	mounts, err := vaultClient.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list Vault mounts: %w", err)
	}

	if _, exists := mounts["consul/"]; exists {
		logger.Info(" [EVALUATE] Consul secrets engine already enabled")
		logger.Info("terminal prompt: ✓ Consul secrets engine is already enabled")
		logger.Info("terminal prompt:   Configure with: vault write consul/config/access address=127.0.0.1:8500 token=<mgmt-token>")
		return nil
	}

	// Enable the engine
	mountInput := &vaultapi.MountInput{
		Type:        "consul",
		Description: "Dynamic Consul ACL token generation for EOS services",
		Config: vaultapi.MountConfigInput{
			DefaultLeaseTTL: config.DefaultTTL,
			MaxLeaseTTL:     config.MaxTTL,
		},
	}

	if err := vaultClient.Sys().Mount("consul", mountInput); err != nil {
		return fmt.Errorf("failed to enable Consul secrets engine: %w", err)
	}

	// EVALUATE - Verify enablement
	logger.Info(" [EVALUATE] Verifying Consul secrets engine is enabled")

	mounts, err = vaultClient.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to verify Consul secrets engine: %w", err)
	}

	if _, exists := mounts["consul/"]; !exists {
		return fmt.Errorf("Consul secrets engine not found after enablement")
	}

	logger.Info(" [EVALUATE] Consul secrets engine enabled successfully")
	logger.Info("terminal prompt: ✓ Consul secrets engine enabled")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next steps to complete configuration:")
	logger.Info("terminal prompt:   1. Create Consul management token: consul acl token create -description='Vault management' -policy-name='vault-mgmt'")
	logger.Info("terminal prompt:   2. Configure Vault: vault write consul/config/access address=127.0.0.1:8500 token=<token>")
	logger.Info("terminal prompt:   3. Create role: vault write consul/roles/eos-role policies=eos-policy ttl=1h max_ttl=24h")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Or use: eos update vault --enable-consul-secrets --consul-token=<token>")

	return nil
}
