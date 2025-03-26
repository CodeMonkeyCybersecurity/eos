/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
package cmd

import (
	"eos/cmd/create"
	"eos/cmd/enable"
	"eos/cmd/secure"
	"eos/cmd/delete"
	"eos/cmd/delphi"
	"eos/cmd/read"
	"eos/cmd/logs"
	"eos/cmd/update"
        "eos/cmd/refresh"
        "eos/cmd/install"
	"eos/cmd/treecat"
	"eos/pkg/logger"
	"eos/pkg/utils"

	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var log *zap.Logger // Global logger instance

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
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

// Register all subcommands in the init function
func init() {
	rootCmd.AddCommand(create.CreateCmd)
	rootCmd.AddCommand(read.ReadCmd)
	rootCmd.AddCommand(update.UpdateCmd)
	rootCmd.AddCommand(delete.DeleteCmd)
        rootCmd.AddCommand(install.InstallCmd)
	rootCmd.AddCommand(refresh.RefreshCmd)
	rootCmd.AddCommand(logs.LogsCmd)
	rootCmd.AddCommand(enable.EnableCmd)
	rootCmd.AddCommand(secure.SecureCmd)
	rootCmd.AddCommand(delphi.DelphiCmd)
	rootCmd.AddCommand(treecatCmd)
}

// Execute starts the CLI
func Execute() {
	// Initialize the logger once globally
	logger.Initialize()
	defer logger.Sync()

	// Assign the logger instance globally for reuse
	log = logger.GetLogger()

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		log.Error("CLI execution error", zap.Error(err))
		os.Exit(1)
	}
}
