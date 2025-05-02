// pkg/vault/phase_delete.go

package vault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"go.uber.org/zap"
)

// GetVaultWildcardPurgePaths returns filesystem wildcards that match legacy or snap Vault installations
// for cleanup during reinstallation or reset.
func GetVaultWildcardPurgePaths() []string {
	return []string{
		shared.VaultLegacyConfigWildcard, // wildcard for legacy configs
		"/var/snap/vault*",               // snap installs
		shared.VaultLogWildcard,          // log spill
		shared.VaultDir,
		shared.EosRunDir,
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

// Purge removes Vault repo artifacts and paths based on the Linux distro.
// It returns a list of removed files and a map of errors keyed by path.
func Purge(distro string, log *zap.Logger) (removed []string, errs map[string]error) {
	errs = make(map[string]error)
	log.Info("🧹 Starting full Vault purge sequence", zap.String("distro", distro))

	pathsToRemove := []string{}

	switch distro {
	case "debian":
		pathsToRemove = append(pathsToRemove, shared.AptKeyringPath, shared.AptListPath)
	case "rhel":
		pathsToRemove = append(pathsToRemove, shared.DnfRepoFilePath)
	default:
		log.Warn("⚠️ No package manager cleanup defined for distro", zap.String("distro", distro))
	}

	pathsToRemove = append(pathsToRemove, shared.VaultBinaryPath)

	for _, path := range pathsToRemove {
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				log.Info("ℹ️ File already absent", zap.String("path", path))
				continue
			}
			log.Error("❌ Failed to remove file", zap.String("path", path), zap.Error(err))
			errs[path] = fmt.Errorf("failed to remove %s: %w", path, err)
		} else {
			log.Info("✅ Removed file", zap.String("path", path))
			removed = append(removed, path)
		}
	}

	// Safe systemd reload with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "systemctl", "daemon-reexec").Run(); err != nil {
		log.Warn("⚠️ Failed daemon-reexec", zap.Error(err))
	}
	if err := exec.CommandContext(ctx, "systemctl", "daemon-reload").Run(); err != nil {
		log.Warn("⚠️ Failed daemon-reload", zap.Error(err))
	}

	log.Info("✅ Vault purge complete", zap.Int("paths_removed", len(removed)), zap.Int("errors", len(errs)))
	return removed, errs
}

// VaultDelete removes a secret at the given KV v2 path
func VaultDelete(path string, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Delete(context.Background(), path)
}

// VaultDestroy permanently deletes a secret at the given KV v2 path
func VaultPurge(path string, log *zap.Logger) error {
	client, err := GetPrivilegedVaultClient(log)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Destroy(context.Background(), path, []int{1}) // TODO To truly destroy all versions, we can add a version-walk helper
}
