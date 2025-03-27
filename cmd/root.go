package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	// Eos commands
	"eos/cmd/create"
	"eos/cmd/delete"
	"eos/cmd/deploy"
	"eos/cmd/logs"
	"eos/cmd/read"
	"eos/cmd/refresh"
	"eos/cmd/secure"
	"eos/cmd/update"

	// Hecate commands (aliased to avoid conflicts)
	hecateBackup "eos/cmd/hecate/backup"
	hecateCreate "eos/cmd/hecate/create"
	hecateDelete "eos/cmd/hecate/delete"
	hecateDeploy "eos/cmd/hecate/deploy"
	hecateInspect "eos/cmd/hecate/inspect"
	hecateRestore "eos/cmd/hecate/restore"
	hecateUpdate "eos/cmd/hecate/update"

	"eos/pkg/logger"
	"eos/pkg/utils"
)

var log = logger.L()

// hecateCmd groups reverse proxy–related commands.
var hecateCmd = &cobra.Command{
	Use:   "hecate",
	Short: "Manage and configure reverse proxy settings for Hecate",
	Long:  "Hecate commands allow you to deploy, inspect, and manage reverse proxy configurations.",
}

var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for managing local and remote environments and reverse proxy configurations",
	Long: `Eos is a command-line application for managing processes, users, hardware, backups, 
and reverse proxy configurations via Hecate.`,
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Eos CLI started successfully.")
		if !utils.CheckSudo() {
			log.Error("Sudo privileges are required to create a backup.")
			return
		}
		// Example: Process the config path
		configPath := filepath.Join(".", "config", "default.yaml")
		log.Info("Loaded configuration", zap.String("path", configPath))
	},
}

func RegisterCommands() {
	// Register Eos commands at the root
	eosCommands := []*cobra.Command{
		create.CreateCmd,
		read.ReadCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		deploy.DeployCmd,
		refresh.RefreshCmd,
		logs.LogsCmd,
		secure.SecureCmd,
		deploy.DeployCmd,
	}
	for _, cmd := range eosCommands {
		RootCmd.AddCommand(cmd)
	}

	// Register Hecate commands under the hecate group
	hecateSubcommands := []*cobra.Command{
		hecateCreate.CreateCmd,
		hecateDelete.DeleteCmd,
		hecateDeploy.DeployCmd,
		hecateInspect.InspectCmd,
		hecateBackup.BackupCmd,
		hecateRestore.RestoreCmd,
		hecateUpdate.UpdateCmd,
	}
	for _, cmd := range hecateSubcommands {
		hecateCmd.AddCommand(cmd)
	}

	// Add the hecate grouping command to the root command
	RootCmd.AddCommand(hecateCmd)
}

func Execute() {
	// Initialize the logger once globally
	if logger.GetLogger() == nil {
		logger.Initialize()
	}
	defer logger.Sync()

	// Assign the logger instance globally for reuse
	log = logger.GetLogger()

	// Register commands
	RegisterCommands()

	// Execute the root command
	if err := RootCmd.Execute(); err != nil {
		log.Error("CLI execution error", zap.Error(err))
		os.Exit(1)
	}
}
