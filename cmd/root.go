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

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// A helper to fetch environment variables with a default fallback
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "eos",
	Short: "Eos CLI for managing local and remote environments",
	Long: `Eos is a command-line application for managing processes, users,
hardware, backups, and more.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Default action when no subcommand is provided
		fmt.Println("Eos CLI: Use 'eos --help' to see available commands.")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		utils.GetLogger().Error(fmt.Sprintf("Command execution failed: %v", err))
		os.Exit(1)
	}
}

var cfgFile string

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.eos.yaml)")
	// Database connection details
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	dbName := getEnv("DB_NAME", "eos_db")
	// Connection string
	dbSSLMode := getEnv("DB_SSLMODE", "disable") // Default to disable if using eos in a local environment only
	connStr := fmt.Sprintf("host=%s port=%s user=%s dbname=%s" sslmode=%s",
		dbHost, dbPort, dbUser, dbName, dbSSLMode)

	// Initialize the global logger
	err = utils.InitializeLogger(db, "/var/log/cyberMonkey/eos.log", utils.InfoLevel, true)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	// Connect to PostgreSQL
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		utils.GetLogger().Fatal(fmt.Sprintf("Failed to connect to PostgreSQL: %v", err))
	// Check database health
	if err := db.Ping(); err != nil {
		utils.GetLogger().Fatal(fmt.Sprintf("Failed to connect to database: %v", err))
	defer db.Close()
	}

	// Add subcommands
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(goCmd)
	rootCmd.AddCommand(deleteCmd)
}
