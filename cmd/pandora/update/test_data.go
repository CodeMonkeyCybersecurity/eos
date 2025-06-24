// cmd/pandora/update/test_data.go
package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdateTestDataCmd overwrites the test-data in Vault,
// falling back to overwriting the local disk version if needed.
var UpdateTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Update test-data in Vault (fallback to disk)",
	Long:  `Updates the stored test-data in Vault. If Vault is unavailable, updates the fallback local test-data.json.`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		client, err := vault.GetVaultClient(rc)
		if err != nil {
			log.Warn("Vault client unavailable, falling back to disk", zap.Error(err))
			client = nil
		} else {
			vault.SetVaultClient(rc, client)
			vault.ValidateAndCache(rc, client)
		}

		newData := shared.GenerateUpdatedTestData()

		if client != nil {
			log.Info("✏️ Attempting to update test-data in Vault...")
			if err := vault.Write(rc, client, shared.TestDataVaultPath, newData); err == nil {
				fmt.Println()
				fmt.Println("✏️ Test Data Update Summary")
				fmt.Println("   Vault: SUCCESS")
				fmt.Printf("     Path: secret/data/%s\n\n", shared.TestDataVaultPath)
				log.Info(" Test-data updated successfully (Vault)")
				return nil
			}
			log.Warn("Vault write failed, falling back to disk", zap.Error(err))
		}

		// Fallback to disk write
		path := filepath.Join(shared.SecretsDir, shared.TestDataFilename)
		raw, err := json.MarshalIndent(newData, "", "  ")
		if err != nil {
			log.Error(" Failed to marshal new test data", zap.Error(err))
			return fmt.Errorf("marshal new test data: %w", err)
		}

		if err := os.WriteFile(path, raw, 0640); err != nil {
			log.Error(" Failed to write updated test data to disk", zap.String("path", path), zap.Error(err))
			return fmt.Errorf("write updated test-data file: %w", err)
		}

		fmt.Println()
		fmt.Println("✏️ Test Data Update Summary")
		fmt.Println("   Disk: SUCCESS")
		fmt.Printf("     Path: %s\n\n", path)
		log.Info(" Test-data updated successfully (fallback)", zap.String("path", path))
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateTestDataCmd)
}
