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
	"github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

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

		client, err := vault.EnsurePrivilegedVaultClient(log)
		if err != nil {
			log.Warn("⚠️ Vault privileged client unavailable", zap.Error(err))
			client = nil // Will trigger fallback to disk
		} else {
			validateAndCache(client, log)
		}

		return writeTestDataToVaultOrFallback(client, data, log)
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

// validateAndCache checks Vault health and caches the client globally if usable.
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

// writeTestDataToVaultOrFallback writes test data into Vault or falls back to disk storage if Vault is unavailable.
func writeTestDataToVaultOrFallback(client *api.Client, data map[string]interface{}, log *zap.Logger) error {
	log.Info("🔐 Attempting to write test data into Vault...")

	vaultPath := "test-data" // Adjust if you want "eos/test-data" instead
	vaultErr := vault.Write(client, vaultPath, data, log)

	if vaultErr == nil {
		log.Info("✅ Uploaded test-data into Vault", zap.String("vault_path", vaultPath))
		printStorageSummary("Vault", vaultPath, "SUCCESS", "Disk", "N/A")
		return nil
	}

	log.Warn("⚠️ Vault write failed — falling back to disk", zap.Error(vaultErr))

	outputPath := diskFallbackPath()
	if err := os.MkdirAll(filepath.Dir(outputPath), DirPerm); err != nil {
		log.Error("❌ Failed to create output directory", zap.String("path", outputPath), zap.Error(err))
		printStorageSummary("Vault", vaultPath, "FAILED", "Disk", "FAILED")
		return fmt.Errorf("vault write failed: %w; fallback mkdir failed: %v", vaultErr, err)
	}

	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Error("❌ Failed to marshal test data", zap.Error(err))
		printStorageSummary("Vault", vaultPath, "FAILED", "Disk", "FAILED")
		return fmt.Errorf("vault write failed: %w; fallback marshal failed: %v", vaultErr, err)
	}

	if err := os.WriteFile(outputPath, raw, FilePerm); err != nil {
		log.Error("❌ Failed to write fallback test data", zap.String("path", outputPath), zap.Error(err))
		printStorageSummary("Vault", vaultPath, "FAILED", "Disk", "FAILED")
		return fmt.Errorf("vault write failed: %w; fallback disk write failed: %v", vaultErr, err)
	}

	log.Info("💾 Fallback to disk succeeded", zap.String("disk_path", outputPath))
	printStorageSummary("Vault", vaultPath, "FAILED", "Disk", "SUCCESS")
	return nil
}

func printStorageSummary(primary string, primaryPath string, primaryResult string, fallback string, fallbackResult string) {
	fmt.Println()
	fmt.Println("🔒 Test Data Storage Summary")
	fmt.Printf("  %s: %s\n", primary, primaryResult)
	if primaryResult == "SUCCESS" {
		fmt.Printf("    📂 Path: %s\n", primaryPath)
	}
	if fallback != "N/A" {
		fmt.Printf("  %s: %s\n", fallback, fallbackResult)
		if fallbackResult == "SUCCESS" {
			fmt.Printf("    📂 Path: %s\n", diskFallbackPath())
		}
	}
	fmt.Println()
}

func diskFallbackPath() string {
	return filepath.Join(shared.SecretsDir, TestDataFilename)
}

func init() {
	CreateCmd.AddCommand(CreateTestDataCmd)
}
