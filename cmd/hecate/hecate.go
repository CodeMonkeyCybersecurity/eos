// cmd/hecate/hecacte.go

package hecate

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/backup"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/deploy"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/read"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/restore"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/update"
	"go.uber.org/zap"
)

// HecateCmd groups reverse proxy–related commands.
var HecateCmd = &cobra.Command{
	Use:     "hecate",
	Short:   "Manage and configure reverse proxy settings for Hecate",
	Long:    "Hecate commands allow you to deploy, inspect, and manage reverse proxy configurations.",
	Aliases: []string{"h"},

	// You can optionally add a Run function if you want to provide default behavior when no subcommand is used.
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {

		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Initialize the shared logger for the entire deploy package

	// Register Hecate subcommands
	HecateCmd.AddCommand(create.CreateCmd)
	HecateCmd.AddCommand(delete.DeleteCmd)
	HecateCmd.AddCommand(deploy.DeployCmd)
	HecateCmd.AddCommand(read.ReadCmd)
	HecateCmd.AddCommand(backup.BackupCmd)
	HecateCmd.AddCommand(restore.RestoreCmd)
	HecateCmd.AddCommand(update.UpdateCmd)

	// TODO: Example persistent flags: DelphiCmd.PersistentFlags().String("config", "", "Path to the Delphi configuration file")

}
