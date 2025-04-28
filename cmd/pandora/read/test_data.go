// cmd/pandora/inspect/test_data.go
package read

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

		var client *api.Client
		var out map[string]interface{}
		var vaultReadErr error

		client, err := vault.EnsurePrivilegedVaultClient(log)
		if err != nil {
			log.Warn("⚠️ Vault client unavailable, falling back to disk", zap.Error(err))
			return inspectFromDisk(log)
		}

		vault.SetVaultClient(client, log)
		validateAndCache(client, log)

		log.Info("🔍 Attempting to read test-data from Vault...")
		if err := vault.Read(client, testDataVaultPath, &out, log); err != nil {
			vaultReadErr = err
			if vault.IsSecretNotFound(err) {
				log.Warn("⚠️ Test-data not found in Vault, attempting disk fallback...", zap.Error(err))
			} else {
				log.Error("❌ Vault read error", zap.String("vault_path", testDataVaultPath), zap.Error(err))
				return fmt.Errorf("vault read failed at '%s': %w", testDataVaultPath, err)
			}
		}

		// If Vault read succeeded
		if vaultReadErr == nil {
			printData(out, "Vault", "secret/data/"+testDataVaultPath)
			log.Info("✅ Test-data read successfully from Vault")
			return nil
		}

		// Otherwise fallback
		log.Info("🔍 Attempting fallback to disk...")

		if fallbackErr := inspectFromDisk(log); fallbackErr != nil {
			log.Error("❌ Both Vault and disk fallback failed",
				zap.String("vault_path", testDataVaultPath),
				zap.Error(vaultReadErr),
				zap.Error(fallbackErr),
			)
			return fmt.Errorf(
				"vault read failed at '%s' (%v); disk fallback also failed (%v)",
				testDataVaultPath, vaultReadErr, fallbackErr,
			)
		}

		log.Info("✅ Test-data read successfully from fallback")
		return nil
	}),
}

func inspectFromDisk(log *zap.Logger) error {
	log.Info("🔍 Attempting to read test-data from disk fallback...")

	path := filepath.Join(shared.SecretsDir, testDataFilename)
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Warn("⚠️ Fallback test-data file not found", zap.String("path", path))
			return fmt.Errorf("no test-data found in Vault or disk")
		}
		log.Error("❌ Failed to read fallback test-data", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("disk fallback read failed: %w", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		log.Error("❌ Invalid fallback test-data format", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("invalid fallback data format: %w", err)
	}

	printData(out, "Disk", path)
	log.Info("✅ Test-data read successfully from fallback")
	return nil
}

func printData(data map[string]interface{}, source, path string) {
	fmt.Println()
	fmt.Println("🔒 Test Data Contents:")
	raw, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(raw))
	fmt.Println()

	printInspectSummary(source, path)
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
	ReadCmd.AddCommand(InspectTestDataCmd)
}
