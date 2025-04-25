// cmd/sync/vault.go

package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

var SyncVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Syncs fallback secrets into Vault",
	Long: `Syncs all fallback secrets stored locally (e.g. from /var/lib/eos/secrets)
into Vault, then removes them from disk if the sync is successful.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		vault.EnsureVaultEnv(log)

		client, err := vault.NewClient(log)
		if err != nil {
			fmt.Println("❌ Failed to create Vault client:", err)
			return nil
		}

		report, client := vault.Check(client, log, nil, "")
		if !report.Initialized || report.Sealed {
			log.Warn("Vault is not ready")
			return fmt.Errorf("vault is not ready")
		}

		secretsDir := shared.SecretsDir
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

			if err := vault.Write(client, base, data, log); err != nil {
				log.Warn("Failed to store fallback data to Vault", zap.Error(err))
				continue
			}

			if err := os.Remove(fullPath); err != nil {
				log.Warn("Synced but could not delete fallback file", zap.String("file", fullPath), zap.Error(err))
			} else {
				fmt.Printf("🗑️  Removed local fallback: %s\n", fullPath)
			}
		}

		fmt.Println("✅ Fallback secrets synced to Vault (if any were found).")
		return nil
	}),
}

func init() {
	SyncCmd.AddCommand(SyncVaultCmd)
}
