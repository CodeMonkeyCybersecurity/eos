package database

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// newHealthCheckCmd creates the database health check command
func newHealthCheckCmd() *cobra.Command {
	var (
		host       string
		port       int
		database   string
		username   string
		password   string
		sslMode    string
		outputJSON bool
	)

	cmd := &cobra.Command{
		Use:     "health-check",
		Aliases: []string{"health", "check"},
		Short:   "Perform database health check",
		Long: `Perform comprehensive health check on a database.

This command provides detailed health assessment:
- Connection test
- Database responsiveness
- Basic query execution
- Performance metrics
- Overall health status

Examples:
  eos database health-check --database mydb            # Basic health check
  eos database health-check --json                     # JSON output
  eos database health-check --host 192.168.1.100 --database delphi`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			logger.Info("Performing database health check",
				zap.String("host", host),
				zap.String("database", database))

			manager := database_management.NewDatabaseManager()

			// Build database configuration
			config := &database_management.DatabaseConfig{
				Type:     database_management.DatabaseTypePostgreSQL,
				Host:     host,
				Port:     port,
				Database: database,
				Username: username,
				Password: password,
				SSLMode:  sslMode,
			}

			// Set defaults
			if config.Host == "" {
				config.Host = "localhost"
			}
			if config.Port == 0 {
				config.Port = 5432
			}
			if config.Username == "" {
				config.Username = "postgres"
			}
			if config.SSLMode == "" {
				config.SSLMode = "disable"
			}

			// Perform health check
			healthCheck, err := manager.PerformHealthCheck(rc, config)
			if err != nil {
				logger.Error("Health check failed", zap.Error(err))
				// Still output what we have
			}

			if outputJSON {
				return outputJSONHealthCheck(healthCheck)
			}

			return outputTableHealthCheck(healthCheck)
		}),
	}

	cmd.Flags().StringVar(&host, "host", "localhost", "Database host")
	cmd.Flags().IntVar(&port, "port", 5432, "Database port")
	cmd.Flags().StringVar(&database, "database", "postgres", "Database name")
	cmd.Flags().StringVar(&username, "username", "postgres", "Database username")
	cmd.Flags().StringVar(&password, "password", "", "Database password")
	cmd.Flags().StringVar(&sslMode, "ssl-mode", "disable", "SSL mode")
	cmd.Flags().BoolVar(&outputJSON, "json", false, "Output in JSON format")

	return cmd
}

func outputJSONHealthCheck(healthCheck *database_management.DatabaseHealthCheck) error {
	data, err := json.MarshalIndent(healthCheck, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputTableHealthCheck(healthCheck *database_management.DatabaseHealthCheck) error {
	fmt.Printf("Database Health Check\n")
	fmt.Printf("====================\n\n")

	// Overall status
	status := "❌ UNHEALTHY"
	if healthCheck.Healthy {
		status = "✅ HEALTHY"
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "Database:\t%s\n", healthCheck.Database)
	fmt.Fprintf(w, "Overall Status:\t%s\n", status)
	fmt.Fprintf(w, "Response Time:\t%s\n", healthCheck.ResponseTime.String())
	fmt.Fprintf(w, "Check Time:\t%s\n", healthCheck.Timestamp.Format("2006-01-02 15:04:05"))

	if healthCheck.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", healthCheck.Error)
	}

	fmt.Printf("\nIndividual Checks:\n")
	fmt.Printf("------------------\n")

	checkW := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(checkW, "Check\tStatus\tMessage\n")
	fmt.Fprintf(checkW, "-----\t------\t-------\n")

	for _, check := range healthCheck.Checks {
		statusIcon := "❌"
		if check.Status == "PASSED" {
			statusIcon = "✅"
		}

		message := check.Message
		if message == "" {
			message = "-"
		}

		fmt.Fprintf(checkW, "%s\t%s %s\t%s\n", check.Name, statusIcon, check.Status, message)
	}
	checkW.Flush()

	// Summary
	passed := 0
	failed := 0
	for _, check := range healthCheck.Checks {
		if check.Status == "PASSED" {
			passed++
		} else {
			failed++
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("--------\n")
	fmt.Printf("Total Checks: %d\n", len(healthCheck.Checks))
	fmt.Printf("Passed: %d\n", passed)
	fmt.Printf("Failed: %d\n", failed)

	if !healthCheck.Healthy {
		fmt.Printf("\n⚠️  Database is not healthy. Please check the failed tests above.\n")
	} else {
		fmt.Printf("\n✅ Database is healthy and functioning normally.\n")
	}

	return nil
}