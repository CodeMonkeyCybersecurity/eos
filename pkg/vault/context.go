/* pkg/vault/context.go */

package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

// GetVaultAddr returns the canonical Vault address based on internal hostname
func getVaultAddr() string {
	hostname := utils.GetInternalHostname()
	return fmt.Sprintf("http://%s:8179", hostname)
}

// SetVaultEnv sets VAULT_ADDR in the environment
func setVaultEnv() (string, error) {
	addr := getVaultAddr()
	if err := os.Setenv("VAULT_ADDR", addr); err != nil {
		return "", fmt.Errorf("failed to set VAULT_ADDR: %w", err)
	}
	fmt.Printf("🔐 VAULT_ADDR is set to %s\n", addr)
	return addr, nil
}
