// pkg/vault/inspect.go
package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// LoadVaultInitResult tries to load the saved Vault initialization result
func LoadVaultInitResult(log *zap.Logger) (*api.InitResponse, error) {
	initRes := new(api.InitResponse)

	// 1. Create a client
	client, err := NewClient(log)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// 2. Correct Read call
	if err := Read(client, shared.VaultInitPath, initRes, log); err != nil {
		return nil, fmt.Errorf("read vault init result: %w", err)
	}

	return initRes, nil
}
