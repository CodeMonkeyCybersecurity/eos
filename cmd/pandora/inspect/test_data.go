// cmd/pandora/inspect/test_data.go
package inspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eoserr"
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

		if !EnsureVaultReadyOrWarn(log) {
			eoserr.PrintError(log, "Vault not ready — skipping Vault reads", eoserr.NewExpectedError(fmt.Errorf("vault unavailable")))
			return nil // <- EOS CLI exits cleanly, no crash
		}

		log.Info("🔍 Attempting to read test-data from Vault...",
			zap.String("vault_path", vaultPath))

		secret, err := vault.ReadSecret(log, vaultPath)
		if err != nil {
			if vault.IsNotFoundError(err) {
				log.Warn("⚠️ No secret found at path", zap.String("vault_path", vaultPath))

				if diskErr := inspectFromDisk(log); diskErr != nil {
					eoserr.PrintError(log, "No test data found anywhere", diskErr)
				}

				return nil // ← Reassures Cobra no crash
			}

			log.Error("❌ Vault read error",
				zap.String("vault_path", vaultPath),
				zap.Error(err))
			return fmt.Errorf("vault read failed at '%s': %w", vaultPath, err)
		}

		if eoserr.IsExpectedUserError(err) {
			eoserr.PrintError(log, "Skipping because Vault unavailable", err)
			return nil
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
			return eoserr.NewExpectedError(fmt.Errorf("no fallback test-data found at %s", path))
		}
		log.Error("❌ Failed to read fallback test-data", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("disk fallback read failed: %w", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		log.Error("❌ Invalid fallback test-data format", zap.String("path", path), zap.Error(err))
		return fmt.Errorf("invalid fallback data format: %w", err)
	}

	if len(out) == 0 {
		log.Warn("⚠️ Fallback file loaded but contains no data", zap.String("path", path))
		return eoserr.NewExpectedError(fmt.Errorf("fallback file at %s is empty", path))
	}

	printData(out, "Disk", path)
	log.Info("✅ Test-data read successfully from fallback",
		zap.Int("entries", len(out)),
		zap.String("path", path))
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

func EnsureVaultReadyOrWarn(log *zap.Logger) bool {
	client, err := vault.GetVaultClient(log)
	if err != nil {
		log.Warn("Vault client lookup error", zap.Error(err))
		return false
	}
	if client == nil {
		log.Warn("Vault client not ready — client is nil")
		return false
	}
	return true
}

func init() {
	InspectCmd.AddCommand(TestDataCmd)
}
