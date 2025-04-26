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

// GetVaultWildcardPurgePaths returns filesystem wildcards that match legacy or snap Vault installations
// for cleanup during reinstallation or reset.
func GetVaultWildcardPurgePaths() []string {
	return []string{
		"/etc/vault*",      // wildcard for legacy configs
		"/var/snap/vault*", // snap installs
		"/var/log/vault*",  // log spill
		"/opt/vault*",
		"/run/eos*",
	}
}

// GetVaultPurgePaths returns wildcard purge paths for Vault cleanup.
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
		shared.TLSDir,
		shared.VaultAgentCACopyPath,
		shared.EosVaultProfilePath,
	}
}

// DefaultAppRoleOptions returns the default settings used when creating the eos-approle in Vault.
func DefaultAppRoleOptions() shared.AppRoleOptions {
	return shared.AppRoleOptions{
		RoleName:      shared.EosIdentity,
		Policies:      []string{shared.EosVaultPolicy},
		TokenTTL:      "1h",
		TokenMaxTTL:   "4h",
		SecretIDTTL:   "24h",
		ForceRecreate: false,
		RefreshCreds:  false,
	}
}

// VaultPath returns the full Vault path for a logical entry name.
func VaultPath(name string, log *zap.Logger) string {
	if strings.Contains(name, "/") {
		log.Warn("VaultPath should not receive slashes", zap.String("input", name))
	}
	final := fmt.Sprintf("%s/%s", shared.DefaultNamespace, name)
	log.Debug("Resolved Vault path", zap.String("input", name), zap.String("result", final))
	return final
}

// DiskPath constructs a fallback config path like: ~/.config/eos/<name>/config.json
func DiskPath(name string, log *zap.Logger) string {
	var final string
	switch name {
	case shared.VaultInitPath:
		final = shared.VaultInitPath
	default:
		final = filepath.Join(shared.VaultConfigDirDebian, name, shared.DefaultConfigFilename)
	}
	log.Debug("Resolved disk path", zap.String("input", name), zap.String("result", final))
	return final
}

// UserSecretPath returns the Vault KV path for a user's secret material.
// NOTE: Do not log paths directly if they may include sensitive usernames.
func UserSecretPath(username string) string {
	path := fmt.Sprintf("users/%s", username)
	zap.L().Debug("Resolved user secret Vault path", zap.String("username", username), zap.String("path", path))
	return path
}

// GetVaultHealthEndpoint constructs the Vault health check URL based on the configured listener address.
// It defaults to localhost if no explicit environment address is provided.
func GetVaultHealthEndpoint(log *zap.Logger) string {
	host := strings.Split(shared.ListenerAddr, ":")[0]
	endpoint := fmt.Sprintf("https://%s/v1/sys/health", host)
	log.Debug("Resolved Vault health endpoint", zap.String("endpoint", endpoint))
	return endpoint
}

// PrepareVaultDirsAndConfig returns the config dir, config file path, and Vault address,
// and ensures necessary directories are created. Returns an error if critical preparation fails.
func PrepareVaultDirsAndConfig(distro string, log *zap.Logger) (string, string, string, error) {
	var configDir string
	switch distro {
	case "debian", "rhel":
		configDir = shared.VaultConfigDirDebian
	default:
		configDir = shared.VaultConfigDirDebian
	}

	if err := os.MkdirAll(configDir, shared.DirPermStandard); err != nil {
		log.Warn("Failed to create Vault config dir", zap.String("path", configDir), zap.Error(err))
		return "", "", "", fmt.Errorf("create config dir: %w", err)
	}
	if err := os.MkdirAll(shared.VaultDataPath, shared.DirPermStandard); err != nil {
		log.Warn("Failed to create Vault data dir", zap.String("path", shared.VaultDataPath), zap.Error(err))
		return "", "", "", fmt.Errorf("create data dir: %w", err)
	}

	configFile := filepath.Join(configDir, shared.DefaultConfigFilename)
	vaultAddr := shared.GetVaultAddr(log)

	return configDir, configFile, vaultAddr, nil
}
