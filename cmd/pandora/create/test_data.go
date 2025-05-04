// cmd/pandora/create/test_data.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// CreateTestDataCmd generates a test dataset and attempts to upload it into Vault,
// falling back to local disk storage if Vault is unavailable.
var CreateTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Generate and upload test data into Vault (fallback to disk)",
	Long: `This command generates realistic test data (e.g., Alice Wonderland, Bob Builder),
attempts to upload it into Vault, and falls back to saving locally if Vault is unavailable.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-create-test-data")
		data := vault.GenerateTestData()

		client, err := vault.GetVaultClient()
		if err != nil {
			log.Warn("⚠️ Vault client unavailable", zap.Error(err))
			client = nil // Will trigger fallback to disk
		} else {
			vault.ValidateAndCache(client)
		}

		return vault.WriteTestDataToVaultOrFallback(client, data)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateTestDataCmd)
}
