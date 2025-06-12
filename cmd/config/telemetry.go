// cmd/config/telemetry.go

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var TelemetryCmd = &cobra.Command{
	Use:   "telemetry [on|off]",
	Short: "Enable or disable Eos CLI telemetry",
	Args:  cobra.ExactArgs(1),
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		stateFile := filepath.Join(os.Getenv("HOME"), ".eos", "telemetry_on")
		action := args[0]

		log := otelzap.Ctx(rc.Ctx)

		switch action {
		case "on":
			if err := os.MkdirAll(filepath.Dir(stateFile), 0700); err != nil {
				log.Error("Failed to create config directory", zap.Error(err))
				return fmt.Errorf("mkdir failed: %w", err)
			}
			if err := os.WriteFile(stateFile, []byte("on\n"), 0600); err != nil {
				log.Error("Failed to write telemetry toggle file", zap.Error(err))
				return fmt.Errorf("enable telemetry: %w", err)
			}
			log.Info("✅ Telemetry enabled")
		case "off":
			if err := os.Remove(stateFile); err != nil && !os.IsNotExist(err) {
				log.Error("Failed to remove telemetry toggle file", zap.Error(err))
				return fmt.Errorf("disable telemetry: %w", err)
			}
			log.Info("🚫 Telemetry disabled")
		default:
			log.Warn("Invalid telemetry argument", zap.String("arg", action))
			return fmt.Errorf("usage: telemetry [on|off]")
		}

		return nil
	}),
}

func init() {
	ConfigCmd.AddCommand(TelemetryCmd)
}
