package service

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
)

// ServiceCmd is the top-level command for service lifecycle management.
var ServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage declarative service initialization flows",
	Long: `Service commands provide a consistent interface for discovering,
inspecting, and executing declarative initialization flows stored as service
definitions. Service definitions describe health checks, ordered steps, and
idempotency behaviour so that complex bootstrap routines can be executed
reliably across environments.`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return cmd.Help()
	}),
}

func init() {
	ServiceCmd.AddCommand(InitCmd)
	ServiceCmd.AddCommand(HealthCmd)
	ServiceCmd.AddCommand(StatusCmd)
	ServiceCmd.AddCommand(ResetCmd)
	ServiceCmd.AddCommand(LogsCmd)
	ServiceCmd.AddCommand(ListCmd)
}
