// cmd/hecate/hecacte.go

package hecate

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/spf13/cobra"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/backup"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/deploy"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/read"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/restore"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/update"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/logger"
)

// log is a package-level variable for the Zap logger.
var log *zap.Logger

// HecateCmd groups reverse proxy–related commands.
var HecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Manage and configure reverse proxy settings for Hecate",
	Long:  "Hecate commands allow you to deploy, inspect, and manage reverse proxy configurations.",
	// You can optionally add a Run function if you want to provide default behavior when no subcommand is used.
	RunE: eos.Wrap(func(ctx *eos.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := logger.GetLogger()
		log.Info("No subcommand provided for <command>.", zap.String("command", cmd.Use))
		_ = cmd.Help() // Display help if no subcommand is provided
		return nil
	}),
}

func init() {
	// Initialize the shared logger for the entire deploy package
	log = logger.L()

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
