/* pkg/vault/config.go */

package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// ResolveVaultConfigDir returns the Vault config directory based on Linux distro.
func ResolveVaultConfigDir(distro string) string {
	switch distro {
	case "debian", "rhel":
		return shared.VaultConfigDirDebian
	default:
		return shared.VaultConfigDirDebian // future: handle other distros here
	}
}

// WriteVaultHCL renders the Vault server configuration (HCL) dynamically
// and writes it to the expected config file on disk. Ensures the directory exists.
// Returns a wrapped error if writing fails.
func WriteVaultHCL(log *zap.Logger) error {
	vaultAddr := shared.GetVaultAddr(log)
	hcl := shared.RenderVaultConfig(vaultAddr, log)
	configPath := shared.VaultConfigPath

	// 1. Ensure the parent directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Error("failed to create Vault config directory", zap.String("path", dir), zap.Error(err))
		return fmt.Errorf("mkdir vault config dir: %w", err)
	}
	log.Debug("✅ Vault config directory ready", zap.String("path", dir))

	// 2. Write the config file
	if err := WriteToDisk(configPath, []byte(hcl), log); err != nil {
		log.Error("failed to write Vault HCL config", zap.Error(err))
		return fmt.Errorf("write vault hcl: %w", err)
	}

	log.Info("✅ Vault configuration written", zap.String("path", configPath))
	return nil
}
