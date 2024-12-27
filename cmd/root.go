/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
package cmd

import (
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

// A helper to fetch environment variables with a default fallback
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var cfgFile string

func init() {

	// Create
	var createCmd = &cobra.Command{
		Use:   "create [target]",
		Short: "Create new resources (e.g., processes, users, backups)",
		Long:  `The create command allows you to create new resources in the system,
such as processes, users, or backups.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatalf("Please specify what to create, e.g., 'processes'")
			}
			target := args[0]
			fmt.Printf("Creating %s...\n", target)
			// Add your logic here
		},
	}
	
	// Read
	var readCmd = &cobra.Command{
		Use:   "read [target]",
		Short: "Retrieve information about resources",
		Long:  `The read command retrieves information about various resources,
such as processes, users, backups, and more.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatalf("Please specify what to read, e.g., 'processes'")
			}
			target := args[0]
			fmt.Printf("Reading %s...\n", target)
			// Add your logic here
		},
	}
	
	// Update
	var updateCmd = &cobra.Command{
		Use:   "update [target]",
		Short: "Update existing resources",
		Long:  `The update command modifies existing resources, such as processes,
users, or backups, based on the provided parameters.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatalf("Please specify what to update, e.g., 'processes'")
			}
			target := args[0]
			fmt.Printf("Updating %s...\n", target)
			// Add your logic here
		},
	}
	
	// Delete
	var deleteCmd = &cobra.Command{
		Use:   "delete [target]",
		Short: "Remove resources from the system",
		Long:  `The delete command allows you to remove resources, such as processes,
users, or backups, from the system.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				log.Fatalf("Please specify what to delete, e.g., 'processes'")
			}
			target := args[0]
			fmt.Printf("Delete %s...\n", target)
			// Add your logic here
		},
	}

	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(deleteCmd)
}

// Execute starts the CLI
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
