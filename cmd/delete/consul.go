// cmd/delete/consul.go

package delete

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var DeleteConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Remove HashiCorp Consul and all associated data",
	Long: `Remove HashiCorp Consul completely from the system.

This command will:
- Gracefully stop the Consul service
- Remove the Consul package and binary
- Delete configuration files (/etc/consul.d)
- Remove data directories (/var/lib/consul)
- Clean up log files (/var/log/consul)
- Remove the consul user and group
- Remove systemd service files

By default, this operation will prompt for confirmation.

EXAMPLES:
  # Remove Consul with confirmation prompt
  eos delete consul

  # Remove Consul without confirmation (use with caution)
  eos delete consul --force

SAFETY:
  This command performs a complete removal. All Consul data will be lost.
  Make sure to backup any important data before proceeding.`,
	RunE: eos_cli.Wrap(runDeleteConsul),
}

var (
	consulForceDelete bool
)

func runDeleteConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	logger.Info("Starting Consul removal process",
		zap.Bool("force", consulForceDelete))

	// Confirmation prompt unless forced
	if !consulForceDelete {
		prompt := "Are you sure you want to remove Consul? All data will be deleted. This action cannot be undone. [y/N] "

		logger.Info("terminal prompt: " + prompt)
		response, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read user input: %w", err)
		}

		if response != "y" && response != "Y" {
			logger.Info("Consul deletion cancelled by user")
			return nil
		}
	}

	// P0 FIX: Use the actual working RemoveConsul function instead of stub
	logger.Info("Removing Consul using native removal function")
	if err := consul.RemoveConsul(rc); err != nil {
		return fmt.Errorf("consul removal failed: %w", err)
	}

	logger.Info("Consul removal completed successfully")
	return nil
}

func init() {
	DeleteConsulCmd.Flags().BoolVarP(&consulForceDelete, "force", "f", false, "Force deletion without confirmation prompt")

	// Register the command with the delete command
	DeleteCmd.AddCommand(DeleteConsulCmd)
}
