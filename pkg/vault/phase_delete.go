// pkg/vault/phase_delete.go

package vault

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
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
		shared.AgentToken,
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
func Purge(rc *eos_io.RuntimeContext, distro string) (removed []string, errs map[string]error) {
	errs = make(map[string]error)
	log := otelzap.Ctx(rc.Ctx)
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

	// Combine both wildcard and direct purge paths, plus distro-specific
	allPaths := append(GetVaultWildcardPurgePaths(), GetVaultPurgePaths()...)
	allPaths = append(allPaths, pathsToRemove...)

	owner := "vault-purge"

	for _, path := range allPaths {
		if strings.Contains(path, "*") {
			matches, _ := filepath.Glob(path)
			for _, m := range matches {
				if err := eos_unix.RmRF(rc.Ctx, m, owner); err != nil {
					// fallback to sudo rm -rf
					fallbackErr := exec.CommandContext(rc.Ctx, "rm", "-rf", m).Run()
					if fallbackErr != nil {
						errs[m] = fallbackErr
						log.Warn("❌ Failed to remove path (even with sudo)", zap.String("path", m), zap.Error(fallbackErr))
					} else {
						removed = append(removed, m)
						log.Info("✅ Removed with sudo rm -rf", zap.String("path", m))
					}
					errs[m] = err
				} else {
					removed = append(removed, m)
				}
			}
		} else {
			if err := eos_unix.RmRF(rc.Ctx, path, owner); err != nil {
				fallbackErr := exec.CommandContext(rc.Ctx, "rm", "-rf", path).Run()
				if fallbackErr != nil {
					errs[path] = fallbackErr
					log.Warn("❌ Failed to remove path (even with sudo)", zap.String("path", path), zap.Error(fallbackErr))
				} else {
					removed = append(removed, path)
					log.Info("✅ Removed with sudo rm -rf", zap.String("path", path))
				}
				errs[path] = err
			} else {
				removed = append(removed, path)
				log.Info("✅ Removed with eos_unix.Rm", zap.String("path", path))
			}
		}
	}

	// Safe systemd reload
	if err := exec.CommandContext(rc.Ctx, "systemctl", "daemon-reexec").Run(); err != nil {
		log.Warn("⚠️ Failed daemon-reexec", zap.Error(err))
	}
	if err := exec.CommandContext(rc.Ctx, "systemctl", "daemon-reload").Run(); err != nil {
		log.Warn("⚠️ Failed daemon-reload", zap.Error(err))
	}

	log.Info("✅ Vault purge complete", zap.Int("paths_removed", len(removed)), zap.Int("errors", len(errs)))
	return removed, errs
}

// VaultDelete removes a secret at the given KV v2 path
func VaultDelete(rc *eos_io.RuntimeContext, path string) error {
	client, err := GetRootClient(rc)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Delete(context.Background(), path)
}

// VaultDestroy permanently deletes a secret at the given KV v2 path
func VaultPurge(rc *eos_io.RuntimeContext, path string) error {
	client, err := GetRootClient(rc)
	if err != nil {
		return err
	}
	kv := client.KVv2("secret")
	return kv.Destroy(context.Background(), path, []int{1}) // TODO To truly destroy all versions, we can add a version-walk helper
}
