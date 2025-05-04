// cmd/pandora/inspect/test_data.go
package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// InspectTestDataCmd attempts to read test data from Vault,
// falling back to disk if Vault is unavailable.
var InspectTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Inspect test-data from Vault (fallback to disk)",
	Long:  `Reads and displays the test-data stored in Vault, or falls back to local disk.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-inspect-test-data")

		var client *api.Client
		var out map[string]interface{}
		var vaultReadErr error

		client, err := vault.GetVaultClient()
		if err != nil {
			log.Warn("⚠️ Vault client unavailable", zap.Error(err))
			client = nil // Will trigger fallback to disk
		} else {
			vault.ValidateAndCache(client)
		}

		vault.SetVaultClient(client)
		vault.ValidateAndCache(client)

		zap.L().Info("🔍 Attempting to read test-data from Vault...")
		if err := vault.Read(client, shared.TestDataVaultPath, &out); err != nil {
			vaultReadErr = err
			if vault.IsSecretNotFound(err) {
				zap.L().Warn("⚠️ Test-data not found in Vault, attempting disk fallback...", zap.Error(err))
			} else {
				zap.L().Error("❌ Vault read error", zap.String("vault_path", shared.TestDataVaultPath), zap.Error(err))
				return fmt.Errorf("vault read failed at '%s': %w", shared.TestDataVaultPath, err)
			}
		}

		// If Vault read succeeded
		if vaultReadErr == nil {
			vault.PrintData(out, "Vault", "secret/data/"+shared.TestDataVaultPath)
			zap.L().Info("✅ Test-data read successfully from Vault")
			return nil
		}

		// Otherwise fallback
		zap.L().Info("🔍 Attempting fallback to disk...")

		if fallbackErr := vault.InspectFromDisk(); fallbackErr != nil {
			zap.L().Error("❌ Both Vault and disk fallback failed",
				zap.String("vault_path", shared.TestDataVaultPath),
				zap.Error(vaultReadErr),
				zap.Error(fallbackErr),
			)
			return fmt.Errorf(
				"vault read failed at '%s' (%v); disk fallback also failed (%v)",
				shared.TestDataVaultPath, vaultReadErr, fallbackErr,
			)
		}

		zap.L().Info("✅ Test-data read successfully from fallback")
		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(InspectTestDataCmd)
}
