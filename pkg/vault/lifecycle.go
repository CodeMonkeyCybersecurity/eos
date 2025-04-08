/* pkg/vault/lifecycle.go */
package vault

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
)

// Purge removes Vault repo artifacts based on the Linux distro.
// It returns a list of removed files and a map of errors keyed by path.
func purge(distro string) (removed []string, errs map[string]error) {
	errs = make(map[string]error)

	switch distro {
	case "debian":
		paths := []string{
			"/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			"/etc/apt/sources.list.d/hashicorp.list",
		}
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				errs[path] = fmt.Errorf("failed to remove %s: %w", path, err)
			} else {
				removed = append(removed, path)
			}
		}
	case "rhel":
		repoFile := "/etc/yum.repos.d/hashicorp.repo"
		if err := os.Remove(repoFile); err != nil && !os.IsNotExist(err) {
			errs[repoFile] = fmt.Errorf("failed to remove %s: %w", repoFile, err)
		} else {
			removed = append(removed, repoFile)
		}
	}

	return removed, errs
}

// deployAndStoreSecrets automates Vault setup and stores secrets after confirmation.
func deployAndStoreSecrets(name string, secrets map[string]string) error {
	fmt.Println("🚀 Deploying Vault...")

	if err := execute.ExecuteAndLog("eos", "deploy", "vault"); err != nil && !strings.Contains(err.Error(), "already installed") {
		return fmt.Errorf("vault deploy failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "enable", "vault"); err != nil {
		fmt.Println("⚠️ Vault enable failed — manual unseal may be required.")
		return fmt.Errorf("vault enable failed: %w", err)
	}

	if err := execute.ExecuteAndLog("eos", "secure", "vault"); err != nil {
		return fmt.Errorf("vault secure failed: %w", err)
	}

	if !isAvailable() {
		return fmt.Errorf("vault does not appear to be running after setup. Try 'eos logs vault'")
	}

	fmt.Println("✅ Vault is running. Storing secrets...")
	return saveToVault(name, secrets)
}
