package vault

import (
	"os"

	"go.uber.org/zap"
)

func WriteVaultHCL(log *zap.Logger) error {
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = "http://127.0.0.1:8179" // or whatever default you're using
	}

	hcl := RenderVaultConfig(vaultAddr)
	configPath := "/etc/vault.d/vault.hcl" // platform-aware if needed

	return writeToDisk(configPath, []byte(hcl), log)
}
