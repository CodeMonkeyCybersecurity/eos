// cmd/pandora/create/test_data.go
package create

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
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
	RunE: eos.Wrap(func(ctx *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-create-test-data")
		data := shared.GenerateTestData()

		client, err := vault.Authn()
		if err != nil {
			log.Warn("⚠️ Vault auth failed, falling back to disk", zap.Error(err))
			client = nil // triggers fallback to disk
		}

		// Write to Vault or fallback to disk
		return vault.WriteTestDataToVaultOrFallback(client, data)
	}),
}

func init() {
	CreateCmd.AddCommand(CreateTestDataCmd)
}
