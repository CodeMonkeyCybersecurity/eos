// cmd/self/telemetry.go

package self

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry/telemetry_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var TelemetryCmd = &cobra.Command{
	Use:   "telemetry [on|off|status]",
	Short: "Manage Eos CLI telemetry collection",
	Long: `Manage local telemetry collection for Eos CLI usage statistics.

Telemetry data is stored locally in JSONL format and can be analyzed 
to understand usage patterns. No data is sent to external servers.

Commands:
  on     - Enable telemetry collection
  off    - Disable telemetry collection  
  status - Show telemetry status and statistics`,
	Args: cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		stateFile := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_on")
		action := args[0]

		log := otelzap.Ctx(rc.Ctx)

		switch action {
		case "on":
			if err := os.MkdirAll(filepath.Dir(stateFile), shared.SecretDirPerm); err != nil {
				log.Error("Failed to create config directory", zap.Error(err))
				return fmt.Errorf("mkdir failed: %w", err)
			}
			if err := os.WriteFile(stateFile, []byte("on\n"), shared.SecretFilePerm); err != nil {
				log.Error("Failed to write telemetry toggle file", zap.Error(err))
				return fmt.Errorf("enable telemetry: %w", err)
			}
			log.Info(" Telemetry enabled")
			telemetry_management.ShowTelemetryInfo(rc)
		case "off":
			if err := os.Remove(stateFile); err != nil && !os.IsNotExist(err) {
				log.Error("Failed to remove telemetry toggle file", zap.Error(err))
				return fmt.Errorf("disable telemetry: %w", err)
			}
			log.Info(" Telemetry disabled")
		case "status":
			return telemetry_management.ShowTelemetryStatus(rc, stateFile)
		default:
			log.Warn("Invalid telemetry argument", zap.String("arg", action))
			return fmt.Errorf("usage: telemetry [on|off|status]")
		}

		return nil
	}),
}

// All helper functions have been migrated to pkg/telemetry/

func init() {
	SelfCmd.AddCommand(TelemetryCmd)
}
