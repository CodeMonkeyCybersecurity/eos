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
)

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

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
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
	dbHost := "localhost"
	dbPort := "5432"
	dbUser := "postgres"
	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		log.Fatal("Database password not set. Please set the DB_PASSWORD environment variable.")
	}
	dbName := "eosdb"
	// Connection string
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	// Connect to PostgreSQL
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	// Check database health
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	// Initialize the global logger
	err = utils.InitializeLogger(db, "/var/log/eos.log", utils.InfoLevel, true)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	// Add subcommands
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(goCmd)
	rootCmd.AddCommand(deleteCmd)
}
