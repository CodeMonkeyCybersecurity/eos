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

// CreateTestDataCmd generates a local JSON blob of test data for validation.
var CreateTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Generate and upload test data into Vault (fallback to disk)",
	Long: `This command generates realistic test data (e.g., Alice Wonderland, Bob Builder),
attempts to upload it into Vault, and falls back to saving locally if Vault is unavailable.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-create-test-data")

		testData := map[string]interface{}{
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

		// Try to write into Vault
		client, err := vault.GetVaultClient(log)
		if err == nil && client != nil {
			log.Info("🔐 Attempting to store test data into Vault...")
			if err := vault.Write(client, "test-data", testData, log); err == nil {
				log.Info("✅ Test data successfully written into Vault", zap.String("vault_path", "test-data"))
				fmt.Println("✅ Test data written to Vault.")
				return nil
			} else {
				log.Warn("⚠️ Failed to write to Vault, falling back to disk", zap.Error(err))
			}
		} else {
			log.Warn("⚠️ Vault client unavailable, falling back to disk", zap.Error(err))
		}

		// Fallback: write to disk
		outputDir := filepath.Join(shared.SecretsDir)
		outputPath := filepath.Join(outputDir, "test-data.json")
		if err := os.MkdirAll(outputDir, 0750); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
		raw, err := json.MarshalIndent(testData, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal test data: %w", err)
		}
		if err := os.WriteFile(outputPath, raw, 0640); err != nil {
			return fmt.Errorf("write test data file: %w", err)
		}

		log.Info("💾 Test data saved to disk fallback", zap.String("output", outputPath))
		fmt.Printf("💾 Test data saved to disk: %s\n", outputPath)
		return nil
	}),
}

func init() {
	CreateCmd.AddCommand(CreateTestDataCmd)
}
