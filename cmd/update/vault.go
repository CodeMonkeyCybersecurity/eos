// File: cmd/update/vault.go

package update

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// vaultUpdateCmd represents the "update vault" command.
var VaultUpdateCmd = &cobra.Command{
	Use:     "vault",
	Aliases: []string{"sync"},
	Short:   "Updates Vault and syncs any fallback secrets",
	Long: `Runs a snap refresh for Vault, updating it to the latest version.
If Vault is available, this command will also upload fallback secrets from disk to Vault.`,
	Run: func(cmd *cobra.Command, args []string) {
		if os.Geteuid() != 0 {
			log.Fatal("This command must be run with sudo or as root.")
		}

		fmt.Println("🔄 Updating Vault via snap...")
		updateCmd := exec.Command("snap", "refresh", "vault")
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr

		if err := updateCmd.Run(); err != nil {
			log.Fatal("Failed to update Vault: %v", zap.Error(err))
		}
		fmt.Println("✅ Vault updated successfully.")

		// Now sync secrets from disk to Vault if possible
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
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
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
