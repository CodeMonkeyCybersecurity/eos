// cmd/pandora/update/test_data.go
package update

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// UpdateTestDataCmd modifies local test-data.json for Pandora testing.
var UpdateTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Update local test-data.json for Pandora testing",
	Long:  `Adds an extra user or modifies fields in the existing test data.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("update-test-data")

		path := filepath.Join(shared.SecretsDir, "test-data.json")

		data, err := os.ReadFile(path)
		if err != nil {
			log.Error("❌ Failed to read test data", zap.String("path", path), zap.Error(err))
			return fmt.Errorf("read test data: %w", err)
		}

		var blob map[string]interface{}
		if err := json.Unmarshal(data, &blob); err != nil {
			return fmt.Errorf("unmarshal test data: %w", err)
		}

		// Add a new user
		users := blob["users"].([]interface{})
		users = append(users, map[string]interface{}{
			"username": "charlie",
			"fullname": "Charlie Chocolate",
			"email":    "charlie@example.com",
			"groups":   []string{"users", "nextcloud"},
			"password": "SweetVictory!",
		})
		blob["users"] = users

		raw, err := json.MarshalIndent(blob, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal updated data: %w", err)
		}

		if err := os.WriteFile(path, raw, 0640); err != nil {
			return fmt.Errorf("write updated test data: %w", err)
		}

		log.Info("✅ Test data updated", zap.String("path", path))
		fmt.Printf("✅ Test data updated and saved: %s\n", path)
		return nil
	}),
}

func init() {
	UpdateCmd.AddCommand(UpdateTestDataCmd)
}
