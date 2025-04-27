// cmd/pandora/create/test_data.go
package create

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// 1. Generate the testData struct
// 2. Open Vault client
// 3. Try vault.Write(client, "test-data", testData, log)
// 4. If success: ✅
// 5. If Vault fails: fallback to WriteToDisk(path, testData, log)
// CreateTestDataCmd generates a test dataset and attempts to upload it into Vault,
// falling back to local disk storage if Vault is unavailable.
var CreateTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Generate and upload test data into Vault (fallback to disk)",
	Long: `This command generates realistic test data (e.g., Alice Wonderland, Bob Builder),
attempts to upload it into Vault, and falls back to saving locally if Vault is unavailable.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-create-test-data")

		data := generateTestData()
		return writeTestDataToVaultOrFallback(data, log)
	}),
}

const (
	TestDataVaultPath = "test-data"
	TestDataFilename  = "test-data.json"
	DirPerm           = 0750
	FilePerm          = 0640
)

// generateTestData returns a realistic in-memory test dataset for validation workflows.
func generateTestData() map[string]interface{} {
	return map[string]interface{}{
		"users": []map[string]interface{}{
			{
				"username": "alice",
				"fullname": "Alice Wonderland",
				"email":    "alice@example.com",
				"groups":   []string{"users", "nextcloud", "keycloak"},
				"password": "S3cr3tP@ssw0rd!",
			},
			{
				"username": "bob",
				"fullname": "Bob Builder",
				"email":    "bob@example.com",
				"groups":   []string{"admins", "ldap", "scim"},
				"password": "CanWeFixItYesWeCan!",
			},
		},
		"groups": []string{"users", "admins", "nextcloud", "keycloak", "ldap", "scim"},
		"services": map[string]string{
			"wazuh_api_url": "https://wazuh.example.com",
			"keycloak_url":  "https://keycloak.example.com",
			"nextcloud_url": "https://nextcloud.example.com",
		},
	}
}

// writeTestDataToVaultOrFallback writes test data into Vault or falls back to disk storage if Vault is unavailable.
func writeTestDataToVaultOrFallback(data map[string]interface{}, log *zap.Logger) error {
	log.Info("🔐 Attempting to write test data into Vault...")

	vaultErr := vault.Write(nil, TestDataVaultPath, data, log)
	if vaultErr == nil {
		log.Info("✅ Test data written into Vault successfully", zap.String("path", TestDataVaultPath))
		return nil
	}

	log.Warn("⚠️ Failed to write to Vault", zap.Error(vaultErr))

	outputPath := diskFallbackPath()

	if err := os.MkdirAll(filepath.Dir(outputPath), DirPerm); err != nil {
		log.Error("❌ Failed to create output directory", zap.String("path", outputPath), zap.Error(err))
		return fmt.Errorf("create output dir: %w", err)
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Error("❌ Failed to marshal test data", zap.Error(err))
		return fmt.Errorf("marshal test data: %w", err)
	}

	if err := os.WriteFile(outputPath, raw, FilePerm); err != nil {
		log.Error("❌ Failed to write fallback test data", zap.String("path", outputPath), zap.Error(err))
		return fmt.Errorf("vault write failed: %w; fallback disk write failed: %v", vaultErr, err)
	}

	log.Warn("⚠️ Vault unavailable — test data stored ONLY on local disk fallback", zap.String("path", outputPath))
	return vaultErr
}

func diskFallbackPath() string {
	return filepath.Join(shared.SecretsDir, TestDataFilename)
}

func init() {
	CreateCmd.AddCommand(CreateTestDataCmd)
}
