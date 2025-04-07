// cmd/hecate/hecacte.go

package hecate

import (
	"github.com/spf13/cobra"
eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"

	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/backup"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/create"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/delete"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/deploy"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/inspect"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/restore"
	"github.com/CodeMonkeyCybersecurity/eos/cmd/hecate/update"
)

// HecateCmd groups reverse proxy–related commands.
var HecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Manage and configure reverse proxy settings for Hecate",
	Long:  "Hecate commands allow you to deploy, inspect, and manage reverse proxy configurations.",
	// You can optionally add a Run function if you want to provide default behavior when no subcommand is used.
	RunE: eos.Wrap(func(cmd *cobra.Command, args []string) error {
	    // For example, display help if no subcommand is provided.
	     cmd.Help()
		return nil 
	}),
}

func init() {
	// Register Hecate subcommands
	HecateCmd.AddCommand(create.CreateCmd)
	HecateCmd.AddCommand(delete.DeleteCmd)
	HecateCmd.AddCommand(deploy.DeployCmd)
	HecateCmd.AddCommand(inspect.InspectCmd)
	HecateCmd.AddCommand(backup.BackupCmd)
	HecateCmd.AddCommand(restore.RestoreCmd)
	HecateCmd.AddCommand(update.UpdateCmd)

	// TODO: Example persistent flags: DelphiCmd.PersistentFlags().String("config", "", "Path to the Delphi configuration file")

}
