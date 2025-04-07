// pkg/vault/env.go
package vault

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

// SetVaultEnv sets the VAULT_ADDR environment variable to the correct internal URL
func setVaultEnv() {
	hostname := utils.GetInternalHostname()
	vaultAddr := fmt.Sprintf("http://%s:8179", hostname)
	os.Setenv("VAULT_ADDR", vaultAddr)
	fmt.Printf("🔐 VAULT_ADDR is set to %s\n", vaultAddr)
}
