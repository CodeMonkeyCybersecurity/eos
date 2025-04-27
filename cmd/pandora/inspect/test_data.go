// cmd/pandora/inspect/test_data.go
package inspect

import (
	"fmt"
	"os"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// InspectTestDataCmd reads and prints the test-data.json for Pandora testing.
var InspectTestDataCmd = &cobra.Command{
	Use:   "test-data",
	Short: "Inspect local test-data.json for Pandora testing",
	Long:  `Prints out the generated test data file for inspection.`,
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("inspect-test-data")

		path := filepath.Join(shared.SecretsDir, "test-data.json")

		data, err := os.ReadFile(path)
		if err != nil {
			log.Error("❌ Failed to read test data", zap.String("path", path), zap.Error(err))
			return fmt.Errorf("read test data: %w", err)
		}

		fmt.Println(string(data))
		log.Info("✅ Test data displayed", zap.String("path", path))
		return nil
	}),
}

func init() {
	InspectCmd.AddCommand(InspectTestDataCmd)
}
