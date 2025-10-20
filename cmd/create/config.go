// cmd/create/config.go

package create

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	hecateConfigMode bool
	configOutputPath string
	interactiveMode  bool
)

func init() {
	CreateCmd.AddCommand(createConfigCmd)

	createConfigCmd.Flags().BoolVar(&hecateConfigMode, "hecate", false, "Generate Hecate reverse proxy configuration")
	createConfigCmd.Flags().StringVarP(&configOutputPath, "output", "o", "hecate-config.yaml", "Output file path")
	createConfigCmd.Flags().BoolVarP(&interactiveMode, "interactive", "i", true, "Interactive mode (default: true)")
}

// createConfigCmd creates configuration files
var createConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Generate configuration files interactively",
	Long: `Generate configuration files for Hecate or other services.

This command helps you create configuration files through an interactive wizard.

Examples:
  eos create config --hecate                        # Generate hecate-config.yaml interactively
  eos create config --hecate --output custom.yaml  # Custom output file
  eos create config --hecate --no-interactive      # Generate example config`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Validate that a config type was specified
		if !hecateConfigMode {
			logger.Error("No configuration type specified")
			logger.Info("terminal prompt: Please specify a configuration type:")
			logger.Info("terminal prompt:   --hecate    Generate Hecate reverse proxy config")
			return fmt.Errorf("no configuration type specified. Use --hecate")
		}

		// Generate Hecate configuration
		if hecateConfigMode {
			logger.Info("Generating Hecate configuration",
				zap.String("output_path", configOutputPath),
				zap.Bool("interactive", interactiveMode))

			if err := hecate.GenerateConfigFile(rc, configOutputPath, interactiveMode); err != nil {
				return fmt.Errorf("failed to generate Hecate config: %w", err)
			}

			return nil
		}

		return fmt.Errorf("unknown configuration type")
	}),
}
