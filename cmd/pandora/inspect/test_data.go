// cmd/pandora/inspect/test_data.go
package inspect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// InspectTestDataCmd attempts to read test data from Vault,
// falling back to disk if Vault is unavailable.
var InspectTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Inspect test-data from Vault (fallback to disk)",
	Long:  `Reads and displays the test-data stored in Vault, or falls back to local disk.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-inspect-test-data")
		const vaultPath = "test-data"

		client, err := vault.EnsurePrivilegedVaultClient(log)
		useVault := true

		if err != nil {
			log.Warn("⚠️ Vault client unavailable, falling back to disk", zap.Error(err))
			useVault = false
		}

		var data []byte
		if useVault {
			log.Info("🔍 Attempting to read test-data from Vault...")
			var out map[string]interface{}
			err := vault.Read(client, vaultPath, &out, log)
			if err != nil {
				log.Warn("⚠️ Vault read failed, falling back to disk", zap.Error(err))
				useVault = false
			} else {
				pretty, _ := json.MarshalIndent(out, "", "  ")
				data = pretty
			}
		}

		if !useVault {
			log.Info("🔍 Attempting to read test-data from disk fallback...")
			fallbackPath := filepath.Join(shared.SecretsDir, "test-data.json")

			data, err = os.ReadFile(fallbackPath)
			if err != nil {
				log.Error("❌ Failed to read test-data from fallback disk", zap.String("path", fallbackPath), zap.Error(err))
				return fmt.Errorf("failed to read test-data: %w", err)
			}
		}

		fmt.Println()
		fmt.Println("🔒 Test Data Contents:")
		fmt.Println(string(data))
		fmt.Println()

		log.Info("✅ Test-data displayed successfully")
		return nil
	}),
}

func init() {
	InspectCmd.AddCommand(InspectTestDataCmd)
}
