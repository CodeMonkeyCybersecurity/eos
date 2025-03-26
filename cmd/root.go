package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"eos/cmd/create"
	"eos/cmd/delete"
	"eos/cmd/deploy"
	"eos/cmd/inspect"
	"eos/cmd/install"
	"eos/cmd/logs"
	"eos/cmd/read"
	"eos/cmd/refresh"
	"eos/cmd/secure"
	"eos/cmd/update"
	"eos/pkg/logger"
	"eos/pkg/utils"
)

var log *zap.Logger // Global logger instance

// RootCmd represents the base command for both eos and hecate commands
var RootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for managing local and remote environments",
	Long: `Eos is a command-line application for managing processes, users,
hardware, backups, and more.`,
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

// Register all subcommands in a unified function
func RegisterCommands() {
	commands := []*cobra.Command{
		create.CreateCmd,
		read.ReadCmd,
		update.UpdateCmd,
		delete.DeleteCmd,
		install.InstallCmd,
		refresh.RefreshCmd,
		logs.LogsCmd,
		secure.SecureCmd,
		deploy.DeployCmd,
		inspect.InspectCmd,
	}

	for _, cmd := range commands {
		RootCmd.AddCommand(cmd)
	}
}

// Execute starts the CLI
func Execute() {
	// Initialize the logger once globally
	logger.Initialize()
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
