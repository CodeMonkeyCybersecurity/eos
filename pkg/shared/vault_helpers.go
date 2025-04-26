// pkg/shared/vault_helpers.go
package shared

import (
	"fmt"
	"os"

	"go.uber.org/zap"
)

// GetVaultAddr returns the Vault address from the VAULT_ADDR environment variable,
// falling back to a default localhost address if unset.
func GetVaultAddr(log *zap.Logger) string {
	if addr := os.Getenv("VAULT_ADDR"); addr != "" {
		log.Debug("✅ Using VAULT_ADDR from environment", zap.String("VAULT_ADDR", addr))
		return addr
	}
	log.Warn("⚠️ VAULT_ADDR not set — falling back to localhost default")
	return fmt.Sprintf(VaultDefaultAddr, LocalhostSAN)
}

// RenderVaultConfig generates a basic Vault server HCL configuration using the provided address.
func RenderVaultConfig(addr string, log *zap.Logger) string {
	if addr == "" {
		log.Warn("⚠️ Blank address provided to RenderVaultConfig — using localhost fallback")
		addr = fmt.Sprintf(VaultDefaultAddr, LocalhostSAN)
	}

	// Warn if TLS files don't exist
	if _, err := os.Stat(TLSKey); err != nil {
		log.Warn("⚠️ TLS key missing when rendering Vault config", zap.String("TLSKey", TLSKey), zap.Error(err))
	}
	if _, err := os.Stat(TLSCrt); err != nil {
		log.Warn("⚠️ TLS cert missing when rendering Vault config", zap.String("TLSCrt", TLSCrt), zap.Error(err))
	}

	log.Info("📜 Rendering Vault server HCL config", zap.String("api_addr", addr))
	return fmt.Sprintf(`
listener "tcp" {
  address         = "0.0.0.0:%s"
  tls_cert_file   = "%s"
  tls_key_file    = "%s"
}
storage "file" {
  path = "%s"
}
disable_mlock = true
api_addr = "%s"
ui = true
`, VaultDefaultPort, TLSCrt, TLSKey, VaultDataPath, addr)
}
