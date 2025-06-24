// cmd/pandora/delete/test_data.go
package delete

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DeleteTestDataCmd attempts to delete test-data from Vault,
// falling back to removing local disk copy if Vault is unavailable.
var DeleteTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Delete test-data from Vault (fallback to disk)",
	Long:  `Deletes the test-data from Vault. Falls back to deleting local test-data.json if Vault is unavailable.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		client, err := vault.GetVaultClient(rc)
		if err != nil {
			log.Warn("Vault client unavailable", zap.Error(err))
			client = nil // Will trigger fallback to disk
		} else {
			vault.ValidateAndCache(rc, client)
		}

		vault.SetVaultClient(rc, client)
		vault.ValidateAndCache(rc, client)

		log.Info("🗑️ Attempting to delete test-data from Vault...")
		err = vault.Delete(rc, client, shared.TestDataVaultPath)
		if err != nil {
			log.Warn("Vault delete failed, falling back to disk", zap.Error(err))
			return vault.DeleteTestDataFromDisk(rc)
		}

		fmt.Println()
		fmt.Println("🗑️  Test Data Deletion Summary")
		fmt.Println("   Vault: SUCCESS")
		fmt.Printf("    📂 Path: secret/data/%s\n\n", shared.TestDataVaultPath)
		log.Info(" Test-data deleted successfully (Vault)")
		return nil
	}),
}

func init() {
	DeleteCmd.AddCommand(DeleteTestDataCmd)
}
