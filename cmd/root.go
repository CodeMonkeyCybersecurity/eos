/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
package cmd

import (
	"eos/cmd/create"
	"eos/cmd/delete"
	"eos/cmd/read"
	"eos/cmd/update"
	"eos/pkg/logger"

	"os"
	"os/user"
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

		// Example: Process the config path
		configPath := filepath.Join(".", "config", "default.yaml")
		log.Info("Loaded configuration", zap.String("path", configPath))
	},
}

func enforceUser() {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatal("Failed to determine current user", zap.Error(err))
	}

	// Enforce that Eos must be run as 'eos_user'
	if currentUser.Username != "eos_user" {
		log.Fatal("Eos must be run as the 'eos_user'. Use 'sudo -u eos_user eos'.")
	}
}

// Register all subcommands in the init function
func init() {
	rootCmd.AddCommand(create.CreateCmd)
	rootCmd.AddCommand(read.ReadCmd)
	rootCmd.AddCommand(update.UpdateCmd)
	rootCmd.AddCommand(delete.DeleteCmd)
}

// Execute starts the CLI
func Execute() {
	// Initialize the logger once globally
	logger.Initialize()
	defer logger.Sync()

	// Assign the logger instance globally for reuse
	log = logger.GetLogger()

	// Enforce user check
	enforceUser()

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		log.Error("CLI execution error", zap.Error(err))
		os.Exit(1)
	}
}
