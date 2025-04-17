/* pkg/vault/client.go */

package vault

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

func NewClient(log *zap.Logger) (*api.Client, error) {
	config := api.DefaultConfig()

	// Let it read VAULT_ADDR, VAULT_TOKEN, etc from the environment
	if err := config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to read Vault env config: %w", err)
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Optionally override token (if not set in ~/.vault-token or VAULT_TOKEN)
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
	}

	return client, nil
}

// SetVaultClient allows other packages to reuse the Vault client.
func SetVaultClient(client *api.Client, log *zap.Logger) {
	vaultClient = client
}

// GetVaultClient returns the cached Vault client (if set).
func GetVaultClient(log *zap.Logger) (*api.Client, error) {
	if vaultClient == nil {
		return nil, fmt.Errorf("vault client is not initialized; call SetVaultClient first")
	}
	return vaultClient, nil
}

// EnsureVaultClient guarantees the Vault client is set, using the privileged eos user.
func EnsureVaultClient(log *zap.Logger) {
	if _, err := EnsureVaultAddr(log); err != nil {
		fmt.Println("⚠️  Failed to set Vault environment:", err)
	}

	if _, err := GetVaultClient(log); err == nil {
		return // already set
	}

	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		fmt.Printf("⚠️  Vault client could not be initialized: %v\n", err)
		return
	}

	SetVaultClient(client, log)
}
