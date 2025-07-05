package container

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ContainerCmd is the root command for container operations
var ContainerCmd = &cobra.Command{
	Use:     "container",
	Aliases: []string{"docker", "compose"},
	Short:   "Manage Docker containers and compose projects",
	Long: `Manage Docker containers and Docker Compose projects.

This command provides comprehensive container management including:
- Installing Docker
- Managing compose projects (start, stop, find)
- Container lifecycle operations
- Project discovery and bulk operations

Examples:
  eos container install                    # Install Docker
  eos container compose find               # Find all compose projects
  eos container compose stop               # Stop all compose projects
  eos container list                       # List running containers`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for container command", zap.String("command", cmd.Use))
		_ = cmd.Help()
		return nil
	}),
}

func init() {
	// Add subcommands to ContainerCmd
	ContainerCmd.AddCommand(NewInstallCmd())
	ContainerCmd.AddCommand(NewComposeCmd())
	ContainerCmd.AddCommand(NewListCmd())
}