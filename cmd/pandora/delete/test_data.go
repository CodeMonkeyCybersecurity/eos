// cmd/pandora/delete/test_data.go
package delete

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// DeleteTestDataCmd attempts to delete test-data from Vault,
// falling back to removing local disk copy if Vault is unavailable.
var DeleteTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Delete test-data from Vault (fallback to disk)",
	Long:  `Deletes the test-data from Vault. Falls back to deleting local test-data.json if Vault is unavailable.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-delete-test-data")

		client, err := vault.GetVaultClient()
		if err != nil {
			log.Warn("⚠️ Vault client unavailable", zap.Error(err))
			client = nil // Will trigger fallback to disk
		} else {
			vault.ValidateAndCache(client)
		}

		vault.SetVaultClient(client)
		vault.ValidateAndCache(client)

		log.Info("🗑️ Attempting to delete test-data from Vault...")
		err = vault.Delete(client, shared.TestDataVaultPath)
		if err != nil {
			log.Warn("⚠️ Vault delete failed, falling back to disk", zap.Error(err))
			return vault.DeleteTestDataFromDisk()
		}

		fmt.Println()
		fmt.Println("🗑️  Test Data Deletion Summary")
		fmt.Println("  🔐 Vault: SUCCESS")
		fmt.Printf("    📂 Path: secret/data/%s\n\n", shared.TestDataVaultPath)
		log.Info("✅ Test-data deleted successfully (Vault)")
		return nil
	}),
}

func init() {
	DeleteCmd.AddCommand(DeleteTestDataCmd)
}
