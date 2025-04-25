// pkg/vault/types.go

package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

//
// ------------------------- HELPERS -------------------------
//

func GetVaultWildcardPurgePaths() []string {
	return []string{
		"/etc/vault*",      // wildcard for legacy configs
		"/var/snap/vault*", // snap installs
		"/var/log/vault*",  // log spill
	}
}

func GetVaultPurgePaths() []string {
	return []string{
		shared.VaultConfigPath,
		shared.VaultAgentConfigPath,
		shared.VaultAgentPassPath,
		shared.VaultServicePath,
		shared.VaultAgentServicePath,
		shared.VaultAgentTokenPath,
		shared.VaultTokenSinkPath,
		shared.SecretsDir,
		shared.EosRunDir,
		shared.VaultDataPath,
		shared.VaultBinaryPath,
		shared.VaultPID,
		shared.AgentPID,
		shared.VaultSystemCATrustPath,
	}
}

func DefaultAppRoleOptions() AppRoleOptions {
	return AppRoleOptions{
		RoleName:      shared.EosIdentity,
		Policies:      []string{"eos-policy"},
		TokenTTL:      "1h",
		TokenMaxTTL:   "4h",
		SecretIDTTL:   "24h",
		ForceRecreate: false,
		RefreshCreds:  false,
	}
}

// VaultPath returns the full KV v2 path for data reads/writes.
func VaultPath(name string, log *zap.Logger) string {
	if strings.Contains(name, "/") {
		log.Warn("vaultPath should not receive slashes", zap.String("input", name))
	}
	final := fmt.Sprintf("eos/%s", name)
	log.Debug("Resolved Vault path", zap.String("input", name), zap.String("result", final))
	return final
}

// DiskPath constructs a fallback config path like: ~/.config/eos/<name>/config.json
func DiskPath(name string, log *zap.Logger) string {
	var final string
	if name == "vault_init" {
		final = filepath.Join(shared.SecretsDir, "vault_init.json")
	} else {
		final = shared.VaultConfigPath(shared.EosIdentity, filepath.Join(name, "DefaultConfigFilename"))
	}
	log.Debug("Resolved disk path", zap.String("input", name), zap.String("result", final))
	return final
}

func UserSecretPath(username string) string {
	return fmt.Sprintf("users/%s", username)
}

// PrepareVaultDirsAndConfig returns the config dir path and config file path,
// and ensures necessary directories are created.
func PrepareVaultDirsAndConfig(distro string, log *zap.Logger) (string, string, string) {
	var configDir string
	if distro == "debian" || distro == "rhel" {
		configDir = shared.VaultConfigDirDebian
	} else {
		configDir = shared.VaultConfigDirSnap
	}

	if err := os.MkdirAll(configDir, shared.DirPermStandard); err != nil {
		log.Warn("Failed to create Vault config dir", zap.String("path", configDir), zap.Error(err))
	}
	if err := os.MkdirAll(shared.VaultDataPath, shared.DirPermStandard); err != nil {
		log.Warn("Failed to create Vault data dir", zap.String("path", shared.VaultDataPath), zap.Error(err))
	}

	configFile := filepath.Join(configDir, shared.VaultConfigFileName)
	vaultAddr := GetVaultAddr()

	return configDir, configFile, vaultAddr
}
