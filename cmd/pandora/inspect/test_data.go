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
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	testDataFilename  = "test-data.json"
	testDataVaultPath = "eos/test-data"
)

// TestDataCmd is 'eos pandora inspect test-data'
var TestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Inspect test data stored in Pandora (Vault)",
	Long:  "Attempts to read a known test secret (eos/test-data) from Vault or fallback.",
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-inspect-test-data")
		vaultPath := "eos/test-data"

		log.Info("🔍 Attempting to read test-data from Vault...",
			zap.String("vault_path", vaultPath))

		secret, err := vault.ReadSecret(log, vaultPath)
		if err != nil {
			// Check if it's a missing/not found error
			if vault.IsNotFoundError(err) || os.IsNotExist(err) {
				log.Warn("No secret found at path",
					zap.String("vault_path", vaultPath))
				return inspectFromDisk(log)
			}

			// Unexpected error — escalate
			log.Error("Vault read error",
				zap.String("vault_path", vaultPath),
				zap.Error(err))
			return fmt.Errorf("vault read failed at '%s': %w", vaultPath, err)
		}

		// Successfully read
		data := secret.Data
		fmt.Println("✅ Secret data retrieved:")
		for k, v := range data {
			fmt.Printf("  %s: %v\n", k, v)
		}

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

func init() {
	InspectCmd.AddCommand(TestDataCmd)
}
