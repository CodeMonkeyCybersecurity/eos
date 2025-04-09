/* pkg/vault/client.go */

package vault

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
)

func NewClient() (*api.Client, error) {
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
