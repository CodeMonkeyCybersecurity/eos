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
		shared.VaultBinaryPath,          // /usr/bin/vault (shared constant)
		"/usr/local/bin/vault",          // Alternate binary location (used by install.go)
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
	log.Info("Starting comprehensive Vault purge sequence",
		zap.String("distro", distro),
		zap.String("operation", "vault_purge"))

	pathsToRemove := []string{}

	switch distro {
	case "debian":
		pathsToRemove = append(pathsToRemove, shared.AptKeyringPath, shared.AptListPath)
		log.Debug("Added Debian-specific cleanup paths",
			zap.Strings("debian_paths", []string{shared.AptKeyringPath, shared.AptListPath}))
	case "rhel":
		pathsToRemove = append(pathsToRemove, shared.DnfRepoFilePath)
		log.Debug("Added RHEL-specific cleanup paths",
			zap.Strings("rhel_paths", []string{shared.DnfRepoFilePath}))
	default:
		log.Warn("No package manager cleanup defined for distribution",
			zap.String("distro", distro),
			zap.String("reason", "unsupported_distro"))
	}

	// Combine both wildcard and direct purge paths, plus distro-specific
	allPaths := append(GetVaultWildcardPurgePaths(), GetVaultPurgePaths()...)
	allPaths = append(allPaths, pathsToRemove...)

	log.Debug("Assembled path list for purge operation",
		zap.Int("total_paths", len(allPaths)),
		zap.Int("wildcard_paths", len(GetVaultWildcardPurgePaths())),
		zap.Int("direct_paths", len(GetVaultPurgePaths())),
		zap.Int("distro_specific_paths", len(pathsToRemove)))

	owner := "vault-purge"

	for i, path := range allPaths {
		log.Debug("Processing path for removal",
			zap.Int("path_index", i+1),
			zap.Int("total_paths", len(allPaths)),
			zap.String("path", path),
			zap.Bool("is_wildcard", strings.Contains(path, "*")))

		if strings.Contains(path, "*") {
			matches, globErr := filepath.Glob(path)
			if globErr != nil {
				log.Warn("Failed to expand wildcard path",
					zap.String("path", path),
					zap.Error(globErr))
				continue
			}

			log.Debug("Wildcard expanded to matches",
				zap.String("wildcard", path),
				zap.Int("match_count", len(matches)),
				zap.Strings("matches", matches))

			for _, m := range matches {
				log.Debug("Attempting to remove wildcard match", zap.String("path", m))
				if err := eos_unix.RmRF(rc.Ctx, m, owner); err != nil {
					log.Debug("Primary removal failed, attempting fallback",
						zap.String("path", m),
						zap.Error(err))
					// fallback to sudo rm -rf
					fallbackErr := exec.CommandContext(rc.Ctx, "rm", "-rf", m).Run()
					if fallbackErr != nil {
						errs[m] = fallbackErr
						log.Warn("Failed to remove path with both methods",
							zap.String("path", m),
							zap.Error(err),
							zap.Error(fallbackErr))
					} else {
						removed = append(removed, m)
						log.Info("Successfully removed path with fallback method",
							zap.String("path", m),
							zap.String("method", "sudo_rm"))
					}
					errs[m] = err
				} else {
					removed = append(removed, m)
					log.Info("Successfully removed path with primary method",
						zap.String("path", m),
						zap.String("method", "eos_unix"))
				}
			}
		} else {
			log.Debug("Attempting to remove direct path", zap.String("path", path))
			if err := eos_unix.RmRF(rc.Ctx, path, owner); err != nil {
				log.Debug("Primary removal failed, attempting fallback",
					zap.String("path", path),
					zap.Error(err))
				fallbackErr := exec.CommandContext(rc.Ctx, "rm", "-rf", path).Run()
				if fallbackErr != nil {
					errs[path] = fallbackErr
					log.Warn("Failed to remove path with both methods",
						zap.String("path", path),
						zap.Error(err),
						zap.Error(fallbackErr))
				} else {
					removed = append(removed, path)
					log.Info("Successfully removed path with fallback method",
						zap.String("path", path),
						zap.String("method", "sudo_rm"))
				}
				errs[path] = err
			} else {
				removed = append(removed, path)
				log.Info("Successfully removed path with primary method",
					zap.String("path", path),
					zap.String("method", "eos_unix"))
			}
		}
	}

	// Safe systemd reload
	log.Debug("Performing systemd daemon reload after purge")
	if err := exec.CommandContext(rc.Ctx, "systemctl", "daemon-reexec").Run(); err != nil {
		log.Warn("Failed systemd daemon-reexec during cleanup",
			zap.Error(err),
			zap.String("operation", "daemon-reexec"))
	} else {
		log.Debug("Successfully completed systemd daemon-reexec")
	}

	if err := exec.CommandContext(rc.Ctx, "systemctl", "daemon-reload").Run(); err != nil {
		log.Warn("Failed systemd daemon-reload during cleanup",
			zap.Error(err),
			zap.String("operation", "daemon-reload"))
	} else {
		log.Debug("Successfully completed systemd daemon-reload")
	}

	log.Info("Vault purge operation completed",
		zap.Int("paths_removed", len(removed)),
		zap.Int("errors", len(errs)),
		zap.String("operation", "vault_purge"),
		zap.String("status", "completed"))

	if len(errs) > 0 {
		log.Debug("Purge completed with errors", zap.Any("error_details", errs))
	}

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
