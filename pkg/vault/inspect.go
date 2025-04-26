// pkg/vault/inspect.go
package vault

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// LoadVaultInitResult tries to load the saved Vault initialization result
func LoadVaultInitResult(log *zap.Logger) (*api.InitResponse, error) {
	initRes := new(api.InitResponse)
	path := DiskPath("vault_init", log)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault init result file: %w", err)
	}
	if err := json.Unmarshal(b, initRes); err != nil {
		return nil, fmt.Errorf("unmarshal vault init result: %w", err)
	}
	log.Info("Vault init result loaded from disk", zap.String("path", path))
	return initRes, nil
}
