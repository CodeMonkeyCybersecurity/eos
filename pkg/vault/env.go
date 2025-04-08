// pkg/vault/env.go
package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

// SetVaultEnv sets the VAULT_ADDR environment variable to the correct internal URL
func setVaultEnv() error {
	hostname := utils.GetInternalHostname()
	vaultAddr := fmt.Sprintf("http://%s:8179", hostname)
	err := os.Setenv("VAULT_ADDR", vaultAddr)
	if err != nil {
		return fmt.Errorf("failed to set VAULT_ADDR: %w", err)
	}
	fmt.Printf("🔐 VAULT_ADDR is set to %s\n", vaultAddr)
	return nil
}
