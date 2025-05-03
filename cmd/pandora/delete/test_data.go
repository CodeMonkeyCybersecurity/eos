// cmd/pandora/delete/test_data.go
package delete

import (
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	testDataVaultPath = "eos/test-data"
	testDataFilename  = "test-data.json"
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
			validateAndCache(client)
		}

		vault.SetVaultClient(client)
		validateAndCache(client)

		log.Info("🗑️ Attempting to delete test-data from Vault...")
		err = vault.Delete(client, testDataVaultPath)
		if err != nil {
			log.Warn("⚠️ Vault delete failed, falling back to disk", zap.Error(err))
			return deleteTestDataFromDisk()
		}

		fmt.Println()
		fmt.Println("🗑️  Test Data Deletion Summary")
		fmt.Println("  🔐 Vault: SUCCESS")
		fmt.Printf("    📂 Path: secret/data/%s\n\n", testDataVaultPath)
		log.Info("✅ Test-data deleted successfully (Vault)")
		return nil
	}),
}

func deleteTestDataFromDisk() error {
	path := filepath.Join(shared.SecretsDir, testDataFilename)
	if err := os.Remove(path); err != nil {
		zap.L().Error("❌ Failed to delete fallback test-data file", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("delete fallback test-data file: %w", err)
	}

	fmt.Println()
	fmt.Println("🗑️  Test Data Deletion Summary")
	fmt.Println("  💾 Disk: SUCCESS")
	fmt.Printf("    📂 Path: %s\n\n", path)
	zap.L().Info("✅ Test-data deleted successfully (fallback)", zap.String("path", path))
	return nil
}

// validateAndCache ensures Vault client health check and cache
func validateAndCache(client *api.Client) {
	report, checked := vault.Check(client, nil, "")
	if checked != nil {
		vault.SetVaultClient(checked)
	}
	if report == nil {
		zap.L().Warn("⚠️ Vault check returned nil — skipping further setup")
		return
	}
	for _, note := range report.Notes {
		zap.L().Warn("⚠️ Vault diagnostic note", zap.String("note", note))
	}
}

func init() {
	DeleteCmd.AddCommand(DeleteTestDataCmd)
}
