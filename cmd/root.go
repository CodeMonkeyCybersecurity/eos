/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
package cmd

import (
	"eos/cmd/create"
	"eos/cmd/delete"
	"eos/cmd/read"
	"eos/cmd/update"
	"eos/pkg/utils"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for managing local and remote environments",
	Long: `Eos is a command-line application for managing processes, users,
hardware, backups, and more.`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath := filepath.Join(".", "config", "default.yaml")
		logFilePath := "/tmp/eos.log"

		// Initialize the logger
		err := utils.InitializeLogger(configPath, logFilePath, utils.Info, true)
		if err != nil {
			log.Fatalf("Failed to initialize logger: %v", err)
		}

		logger := utils.GetLogger()
		logger.Info("Eos CLI started successfully.")
	},
}

func cmd() {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to determine current user: %v", err)
	}

	// Enforce that Eos must be run as 'eos_user'
	if currentUser.Username != "eos_user" {
		log.Fatalf("Eos must be run as the 'eos_user'. Use 'sudo -u eos_user eos'.")
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
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
