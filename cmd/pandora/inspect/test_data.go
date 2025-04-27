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
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-inspect-test-data")

		// Try to create a privileged Vault client first
		client, err := vault.EnsurePrivilegedVaultClient(log)
		if err != nil {
			log.Warn("⚠️ Vault client unavailable, falling back to disk", zap.Error(err))
			return inspectTestDataFromDisk(log)
		}

		// 🛠 Properly cache the Vault client immediately
		vault.SetVaultClient(client, log)
		validateAndCache(client, log)

		log.Info("🔍 Attempting to read test-data from Vault...")
		var out map[string]interface{}
		if err := vault.Read(client, testDataVaultPath, &out, log); err != nil {
			if vault.IsSecretNotFound(err) {
				log.Warn("⚠️ Test-data not found in Vault, falling back to disk", zap.Error(err))
				return inspectTestDataFromDisk(log)
			}
			log.Error("❌ Unexpected Vault error", zap.Error(err))
			return fmt.Errorf("vault read failed: %w", err)
		}

		pretty, _ := json.MarshalIndent(out, "", "  ")
		printTestData(pretty)
		log.Info("✅ Test-data displayed successfully (Vault)")
		return nil
	}),
}

const (
	testDataFilename  = "test-data.json"
	testDataVaultPath = "test-data"
)

func inspectTestDataFromDisk(log *zap.Logger) error {
	log.Info("🔍 Attempting to read test-data from disk fallback...")

	fallbackPath := filepath.Join(shared.SecretsDir, testDataFilename)
	data, err := os.ReadFile(fallbackPath)
	if err != nil {
		log.Error("❌ Failed to read test-data from fallback disk", zap.String("path", fallbackPath), zap.Error(err))
		return fmt.Errorf("failed to read test-data from fallback: %w", err)
	}

	printTestData(data)
	log.Info("✅ Test-data displayed successfully (fallback)", zap.String("path", fallbackPath))
	return nil
}

func printTestData(data []byte) {
	fmt.Println()
	fmt.Println("🔒 Test Data Contents:")
	fmt.Println(string(data))
	fmt.Println()
}

// validateAndCache ensures Vault client health check and cache
func validateAndCache(client *api.Client, log *zap.Logger) {
	report, checked := vault.Check(client, log, nil, "")
	if checked != nil {
		vault.SetVaultClient(checked, log)
	}
	if report == nil {
		log.Warn("⚠️ Vault check returned nil — skipping further setup")
		return
	}
	for _, note := range report.Notes {
		log.Warn("⚠️ Vault diagnostic note", zap.String("note", note))
	}
}

func init() {
	InspectCmd.AddCommand(InspectTestDataCmd)
}
