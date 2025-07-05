// cmd/manage/manage.go

package manage

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ManageCmd is the root command for system management operations
var ManageCmd = &cobra.Command{
	Use:     "manage",
	Aliases: []string{"mgmt", "administer"},
	Short:   "Manage system components via SaltStack",
	Long: `Manage system components such as services, users, cron jobs, and packages using SaltStack.

This command group provides system administration capabilities following the 
assessment→intervention→evaluation model for reliable state management.

Examples:
  eos manage services        # Manage system services
  eos manage users          # Manage user accounts
  eos manage cron           # Manage cron jobs
  eos manage packages       # Manage system packages`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for manage command", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Add subcommands to ManageCmd
	ManageCmd.AddCommand(NewServicesCmd())
	ManageCmd.AddCommand(NewCronCmd())
}