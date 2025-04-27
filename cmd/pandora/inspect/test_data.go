// cmd/pandora/inspect/test_data.go
package inspect

import (
	"encoding/json"
	"errors"
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

const (
	testDataFilename  = "test-data.json"
	testDataVaultPath = "eos/test-data"
)

// InspectTestDataCmd attempts to read test data from Vault,
// falling back to disk if Vault is unavailable.
var InspectTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Inspect test-data from Vault (fallback to disk)",
	Long:  `Reads and displays the test-data stored in Vault, or falls back to local disk.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-inspect-test-data")

		client, err := vault.EnsurePrivilegedVaultClient(log)
		if err != nil {
			log.Warn("⚠️ Vault client unavailable, falling back to disk", zap.Error(err))
			return inspectTestDataFromDisk(log)
		}

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
		printInspectSummary("Vault", "secret/data/"+testDataVaultPath)
		log.Info("✅ Test-data displayed successfully (Vault)")
		return nil
	}),
}

func inspectTestDataFromDisk(log *zap.Logger) error {
	log.Info("🔍 Attempting to read test-data from disk fallback...")

	fallbackPath := filepath.Join(shared.SecretsDir, testDataFilename)
	data, err := os.ReadFile(fallbackPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Warn("⚠️ Test-data not found in fallback disk", zap.String("path", fallbackPath))
			return fmt.Errorf("test-data not found in Vault or fallback disk")
		}
		log.Error("❌ Failed to read fallback test-data", zap.String("path", fallbackPath), zap.Error(err))
		return fmt.Errorf("failed to read fallback test-data: %w", err)
	}

	printTestData(data)
	printInspectSummary("Disk", fallbackPath)
	log.Info("✅ Test-data displayed successfully (fallback)", zap.String("path", fallbackPath))
	return nil
}

func printTestData(data []byte) {
	fmt.Println()
	fmt.Println("🔒 Test Data Contents:")
	fmt.Println(string(data))
	fmt.Println()
}

func printInspectSummary(source, path string) {
	fmt.Println()
	fmt.Println("🔎 Test Data Inspection Summary")
	switch source {
	case "Vault":
		fmt.Printf("  🔐 Source: %s\n", source)
	case "Disk":
		fmt.Printf("  💾 Source: %s\n", source)
	default:
		fmt.Printf("  ❓ Source: %s\n", source)
	}
	fmt.Printf("  📂 Path: %s\n", path)
	fmt.Println()
}

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
