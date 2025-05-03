// cmd/pandora/update/test_data.go
package update

import (
	"encoding/json"
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

// UpdateTestDataCmd overwrites the test-data in Vault,
// falling back to overwriting the local disk version if needed.
var UpdateTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Update test-data in Vault (fallback to disk)",
	Long:  `Updates the stored test-data in Vault. If Vault is unavailable, updates the fallback local test-data.json.`,
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("pandora-update-test-data")

		client, err := vault.EnsurePrivilegedVaultClient()
		if err != nil {
			log.Warn("⚠️ Vault client unavailable, falling back to disk", zap.Error(err))
			client = nil
		} else {
			vault.SetVaultClient(client)
			validateAndCache(client)
		}

		newData := generateUpdatedTestData()

		if client != nil {
			log.Info("✏️ Attempting to update test-data in Vault...")
			if err := vault.Write(client, testDataVaultPath, newData); err == nil {
				fmt.Println()
				fmt.Println("✏️ Test Data Update Summary")
				fmt.Println("  🔐 Vault: SUCCESS")
				fmt.Printf("    📂 Path: secret/data/%s\n\n", testDataVaultPath)
				log.Info("✅ Test-data updated successfully (Vault)")
				return nil
			}
			log.Warn("⚠️ Vault write failed, falling back to disk", zap.Error(err))
		}

		// Fallback to disk write
		path := filepath.Join(shared.SecretsDir, testDataFilename)
		raw, err := json.MarshalIndent(newData, "", "  ")
		if err != nil {
			log.Error("❌ Failed to marshal new test data", zap.Error(err))
			return fmt.Errorf("marshal new test data: %w", err)
		}

		if err := os.WriteFile(path, raw, 0640); err != nil {
			log.Error("❌ Failed to write updated test data to disk", zap.String("path", path), zap.Error(err))
			return fmt.Errorf("write updated test-data file: %w", err)
		}

		fmt.Println()
		fmt.Println("✏️ Test Data Update Summary")
		fmt.Println("  💾 Disk: SUCCESS")
		fmt.Printf("    📂 Path: %s\n\n", path)
		log.Info("✅ Test-data updated successfully (fallback)", zap.String("path", path))
		return nil
	}),
}

func generateUpdatedTestData() map[string]interface{} {
	return map[string]interface{}{
		"users": []map[string]interface{}{
			{
				"username": "alice",
				"fullname": "Alice Wonderland (Updated)",
				"email":    "alice@wonderland.com",
				"groups":   []string{"users", "nextcloud"},
				"password": "UpdatedS3cretP@ss!",
			},
			{
				"username": "bob",
				"fullname": "Bob the Builder (Updated)",
				"email":    "bob@builder.com",
				"groups":   []string{"admins"},
				"password": "YesWeStillCan!",
			},
		},
		"groups": []string{"users", "admins", "nextcloud"},
		"services": map[string]string{
			"wazuh_api_url": "https://new-wazuh.example.com",
		},
	}
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
	UpdateCmd.AddCommand(UpdateTestDataCmd)
}
