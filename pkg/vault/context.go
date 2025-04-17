/* pkg/vault/context.go */

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"go.uber.org/zap"
)

// EnsureVaultAddr ensures VAULT_ADDR is set in the environment and returns it.
func EnsureVaultAddr(log *zap.Logger) (string, error) {
	addr := getVaultAddr()

	if current := os.Getenv("VAULT_ADDR"); current != "" {
		log.Debug("VAULT_ADDR already set", zap.String("VAULT_ADDR", current))
		return current, nil
	}

	if err := os.Setenv("VAULT_ADDR", addr); err != nil {
		return "", fmt.Errorf("failed to set VAULT_ADDR: %w", err)
	}

	log.Info("🔐 VAULT_ADDR was not set — defaulting from internal hostname", zap.String("VAULT_ADDR", addr))
	return addr, nil
}

// GetVaultAddr returns the canonical Vault address based on internal hostname
func getVaultAddr() string {
	hostname := utils.GetInternalHostname()
	return fmt.Sprintf("http://%s:8179", hostname)
}
