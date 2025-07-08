// cmd/pandora/read/test_data.go
package read

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InspectTestDataCmd attempts to read test data from Vault,
// falling back to disk if Vault is unavailable.
var InspectTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Inspect test-data from Vault (fallback to disk)",
	Long:  `Reads and displays the test-data stored in Vault, or falls back to local disk.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		var client *api.Client
		var out map[string]interface{}
		var vaultReadErr error

		client, err := vault.Authn(rc)
		if err != nil {
			log.Warn("Vault auth failed, falling back to disk", zap.Error(err))
			client = nil // triggers fallback to disk
		}

		if client != nil {
			log.Info(" Attempting to read test-data from Vault...")
			if err := vault.Read(rc, client, shared.TestDataVaultPath, &out); err != nil {
				vaultReadErr = err
				if vault.IsSecretNotFound(err) {
					log.Warn("Test-data not found in Vault, attempting disk fallback...", zap.Error(err))
				} else {
					log.Error(" Vault read error", zap.String("vault_path", shared.TestDataVaultPath), zap.Error(err))
					return fmt.Errorf("vault read failed at '%s': %w", shared.TestDataVaultPath, err)
				}
			}
		}

		// If Vault read succeeded
		if vaultReadErr == nil && client != nil {
			vault.PrintData(rc.Ctx, out, "Vault", "secret/data/"+shared.TestDataVaultPath)
			log.Info(" Test-data read successfully from Vault")
			return nil
		}

		// Otherwise fallback to disk
		log.Info(" Attempting fallback to disk...")

		if fallbackErr := vault.InspectFromDisk(rc); fallbackErr != nil {
			log.Error(" Both Vault and disk fallback failed",
				zap.String("vault_path", shared.TestDataVaultPath),
				zap.Error(vaultReadErr),
				zap.Error(fallbackErr),
			)
			return fmt.Errorf(
				"vault read failed at '%s' (%v); disk fallback also failed (%v)",
				shared.TestDataVaultPath, vaultReadErr, fallbackErr,
			)
		}

		log.Info(" Test-data read successfully from fallback")
		return nil
	}),
}

func init() {
	ReadCmd.AddCommand(InspectTestDataCmd)
}
