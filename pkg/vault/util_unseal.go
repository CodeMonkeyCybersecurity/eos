// pkg/vault/util_unseal.go

package vault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

// unsealFromStoredKeys is called when /sys/health returns 503 (sealed). We load the stored vault_init.json (or prompt) and unseal.
func unsealFromStoredKeys(c *api.Client, log *zap.Logger) error {
	initRes, err := LoadInitResultOrPrompt(c, log)
	if err != nil {
		return fmt.Errorf("could not load stored unseal keys: %w", err)
	}
	if err := UnsealVault(c, initRes, log); err != nil {
		return fmt.Errorf("auto‑unseal failed: %w", err)
	}
	// give the client a token so later calls work
	c.SetToken(initRes.RootToken)
	return nil
}
