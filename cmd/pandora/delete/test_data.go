// cmd/pandora/delete/test_data.go
package delete

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// DeleteTestDataCmd removes test-data from Vault (or disk fallback).
var DeleteTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Delete test-data from Vault (or fallback disk copy)",
	Long:  `Deletes the test data secret from Vault. If Vault is unavailable, deletes the local test-data.json.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("delete-test-data")

		client, err := vault.GetVaultClient(log)
		if err == nil {
			err := client.KVv2(shared.VaultMountKV).Delete(context.Background(), "test-data")
			if err == nil {
				log.Info("✅ Test data deleted from Vault")
				fmt.Println("✅ Test data deleted from Vault")
				return nil
			}
			log.Warn("⚠️ Failed to delete from Vault, falling back", zap.Error(err))
		} else {
			log.Warn("⚠️ Vault client unavailable, falling back to disk", zap.Error(err))
		}

		// Fallback: delete from disk
		path := filepath.Join(shared.SecretsDir, "test-data.json")
		if err := os.Remove(path); err != nil {
			log.Error("❌ Failed to delete fallback test data", zap.String("path", path), zap.Error(err))
			return fmt.Errorf("delete fallback test data: %w", err)
		}

		log.Info("✅ Fallback test data deleted", zap.String("path", path))
		fmt.Printf("✅ Test data deleted from fallback: %s\n", path)
		return nil
	}),
}

func init() {
	DeleteCmd.AddCommand(DeleteTestDataCmd)
}
