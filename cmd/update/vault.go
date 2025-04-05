// cmd/update/vault.go

package update

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var VaultUpdateCmd = &cobra.Command{
	Use:     "vault",
	Short:   "Updates Vault and syncs any fallback secrets",
	Long: `Updates Vault based on your system's package manager (e.g., dnf or snap).
Also syncs any fallback secrets from disk into Vault if it's running.`,
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			log.Fatal("This command must be run with sudo or as root.")
		}

		distro := platform.DetectLinuxDistro()
		var updateCmd *exec.Cmd

		switch distro {
		case "rhel":
			fmt.Println("🔄 Updating Vault via dnf...")
			updateCmd = exec.Command("dnf", "upgrade", "-y", "vault")
		case "debian":
			fmt.Println("🔄 Updating Vault via apt...")
			updateCmd = exec.Command("apt", "update")
			if err := updateCmd.Run(); err != nil {
				log.Fatal("Failed to run apt update", zap.Error(err))
			}
			updateCmd = exec.Command("apt", "install", "-y", "vault")
		default:
			log.Fatal("Unsupported or unknown distro", zap.String("distro", distro))
		}

		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr

		if err := updateCmd.Run(); err != nil {
			log.Fatal("Failed to update Vault", zap.Error(err))
		}
		fmt.Println("✅ Vault updated successfully.")

		if err := syncFallbackSecrets(); err != nil {
			log.Warn("Failed to sync fallback secrets", zap.Error(err))
		} else {
			fmt.Println("✅ Fallback secrets synced to Vault (if any were found).")
		}
	},
}

func init() {
	UpdateCmd.AddCommand(VaultUpdateCmd)
}

// syncFallbackSecrets uploads any fallback YAML secrets to Vault if Vault is running
func syncFallbackSecrets() error {
	vault.SetVaultEnv()

	if !vault.IsAvailable() {
		fmt.Println("Vault is not currently available — skipping secret sync.")
		return nil
	}

	secretsDir := "/var/lib/eos/secrets"
	files, err := os.ReadDir(secretsDir)
	if err != nil {
		return fmt.Errorf("failed to read fallback secrets dir: %w", err)
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if !strings.HasSuffix(f.Name(), ".yaml") {
			log.Debug("Skipping non-YAML file", zap.String("file", f.Name()))
			continue
		}

		fullPath := filepath.Join(secretsDir, f.Name())
		base := strings.TrimSuffix(f.Name(), "-fallback.yaml")

		fmt.Printf("📁 Syncing %s -> Vault path: secret/eos/%s/config\n", fullPath, base)

		data := make(map[string]string)
		raw, err := os.ReadFile(fullPath)
		if err != nil {
			log.Warn("Failed to read fallback file", zap.Error(err))
			continue
		}

		if err := yaml.Unmarshal(raw, &data); err != nil {
			log.Warn("Failed to parse fallback YAML", zap.Error(err))
			continue
		}

		if err := vault.SaveToVault(base, data); err != nil {
			log.Warn("Failed to store fallback data to Vault", zap.Error(err))
			continue
		}

		if err := os.Remove(fullPath); err != nil {
			log.Warn("Synced but could not delete fallback file", zap.String("file", fullPath), zap.Error(err))
		} else {
			fmt.Printf("🗑️  Removed local fallback: %s\n", fullPath)
		}
	}

	return nil
}