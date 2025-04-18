/* pkg/vault/client.go */

package vault

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// EnsureVaultClient guarantees the Vault client is set, using the privileged eos user.
func EnsureVaultClient(log *zap.Logger) {
	log.Debug("🔐 Ensuring VAULT_ADDR is configured...")

	if _, err := EnsureVaultAddr(log); err != nil {
		log.Warn("⚠️ Failed to set Vault environment", zap.Error(err))
	}

	// Already initialized?
	if client, err := GetVaultClient(log); err == nil && client != nil {
		log.Debug("✅ Vault client already initialized")
		return
	}

	log.Info("🔐 Attempting to initialize Vault client from environment (VAULT_TOKEN)...")
	client, err := NewClient(log)
	if err == nil {
		log.Info("✅ Vault client created from environment")
		SetVaultClient(client, log)
		return
	}

	log.Warn("⚠️ Failed to create Vault client from environment", zap.Error(err))
	log.Info("🔐 Falling back to Vault Agent AppRole authentication...")

	client, err = GetPrivilegedVaultClient(log)
	if err != nil {
		log.Error("❌ Vault client could not be initialized",
			zap.Error(err),
			zap.String("hint", "Is Vault Agent running? Is /run/eos/vault-agent-eos.token readable? Did you run `eos secure vault`?"),
		)
		return
	}

	log.Info("✅ Vault client initialized via privileged agent")
	SetVaultClient(client, log)
}

func NewClient(log *zap.Logger) (*api.Client, error) {
	config := api.DefaultConfig()

	// Step 1: Read from environment
	if err := config.ReadEnvironment(); err != nil {
		log.Warn("⚠️ Failed to read environment configuration for Vault", zap.Error(err))
		return nil, fmt.Errorf("failed to read Vault env config: %w", err)
	}

	log.Debug("✅ Vault environment config loaded", zap.String("VAULT_ADDR", config.Address))

	client, err := api.NewClient(config)
	if err != nil {
		log.Error("❌ Failed to create Vault API client", zap.Error(err))
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Step 2: Try to set token
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		log.Debug("🔑 VAULT_TOKEN found in environment — assigning to client")
		client.SetToken(token)
	} else {
		log.Debug("🕳️ No VAULT_TOKEN set — relying on fallback or agent token")
	}

	return client, nil
}

func SetVaultClient(client *api.Client, log *zap.Logger) {
	log.Debug("📦 Vault client cached globally")
	vaultClient = client
}

func GetVaultClient(log *zap.Logger) (*api.Client, error) {
	if vaultClient == nil {
		log.Debug("❌ Vault client requested but not initialized")
		return nil, fmt.Errorf("vault client is not initialized; call SetVaultClient first")
	}
	log.Debug("📦 Returning cached Vault client")
	return vaultClient, nil
}
