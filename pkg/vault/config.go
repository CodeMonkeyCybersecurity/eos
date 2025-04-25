/* pkg/vault/config.go */

package vault

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// ResolveVaultConfigDir returns the Vault config directory based on Linux distro.
func ResolveVaultConfigDir(distro string) string {
	switch distro {
	case "debian", "rhel":
		return shared.VaultConfigDirDebian
	default:
		return shared.VaultConfigDirDebian
	}
}

// WriteVaultHCL renders and writes the Vault configuration file.
func WriteVaultHCL(log *zap.Logger) error {
	vaultAddr := shared.GetVaultAddr(log)

	hcl := shared.RenderVaultConfig(vaultAddr, log)
	configPath := shared.VaultConfigPath

	if err := WriteToDisk(configPath, []byte(hcl), log); err != nil {
		log.Error("failed to write Vault HCL config", zap.Error(err))
		return err
	}

	log.Info("✅ Vault configuration written", zap.String("path", configPath))
	return nil
}
