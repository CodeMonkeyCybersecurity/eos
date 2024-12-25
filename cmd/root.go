/*
Copyright © 2024 Henry Oliver henry@cybermonkey.net.au
*/
package cmd

import (
	"database/sql"
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
	err := utils.InitializeLogger(configPath, logFilePath, utils.InfoLevel, true)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	logger := utils.GetLogger()
	logger.Info("Eos CLI started successfully.")
	},
)

func Execute() {
if err := rootCmd.Execute(); err != nil {
	log.Fatalf("Command execution failed: %v", err)
	}
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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		utils.GetLogger().Error(fmt.Sprintf("Command execution failed: %v", err))
		os.Exit(1)
	}
}

var cfgFile string

func init() {
	// define your flags and configuration settings.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.eos.yaml)")
	// Database connection details
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "eos_user")
	dbName := getEnv("DB_NAME", "eos_db")
	// Connection string
	dbSSLMode := getEnv("DB_SSLMODE", "disable") // Default to disable if using eos in a local environment only
	connStr := fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s",
		dbHost, dbPort, dbUser, dbName, dbSSLMode)

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	// Check database health
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping the database: %v", err)
	}

	// Initialize the global logger
	err = utils.InitializeLogger(db, "/var/log/cyberMonkey/eos.log", utils.InfoLevel, true)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

// Create
var createCmd = &cobra.Command{
	Use:   "read [target]",
	Short: "Read information",
	Long:  `Reads information about processes, users, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please specify what to read, e.g., 'processes'")
		}
		target := args[0]
		fmt.Printf("Reading %s...\n", target)
		// Add your logic here
	},
}

func init() {
	rootCmd.AddCommand(readCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Read
var readCmd = &cobra.Command{
	Use:   "read [target]",
	Short: "Read information",
	Long:  `Reads information about processes, users, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please specify what to read, e.g., 'processes'")
		}
		target := args[0]
		fmt.Printf("Reading %s...\n", target)
		// Add your logic here
	},
}

func init() {
	rootCmd.AddCommand(readCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Update
var updateCmd = &cobra.Command{
	Use:   "read [target]",
	Short: "Read information",
	Long:  `Reads information about processes, users, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please specify what to read, e.g., 'processes'")
		}
		target := args[0]
		fmt.Printf("Reading %s...\n", target)
		// Add your logic here
	},
}

func init() {
	rootCmd.AddCommand(readCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Delete
var deleteCmd = &cobra.Command{
	Use:   "read [target]",
	Short: "Read information",
	Long:  `Reads information about processes, users, etc.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			log.Fatalf("Please specify what to read, e.g., 'processes'")
		}
		target := args[0]
		fmt.Printf("Reading %s...\n", target)
		// Add your logic here
	},
}

func init() {
	rootCmd.AddCommand(readCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
	
	// Add subcommands
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(deleteCmd)
}
