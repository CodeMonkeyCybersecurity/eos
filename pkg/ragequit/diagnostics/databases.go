package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckDatabases checks database status
// Migrated from cmd/ragequit/ragequit.go checkDatabases
func CheckDatabases(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Prepare for database checking
	logger.Info("Assessing database status")
	
	homeDir := system.GetHomeDir()
	outputFile := filepath.Join(homeDir, "ragequit-databases.txt")
	
	var output strings.Builder
	output.WriteString("=== Database Diagnostics ===\n")
	output.WriteString(fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339)))
	
	// INTERVENE - Check various database systems
	logger.Debug("Checking database systems")
	
	// PostgreSQL
	if system.CommandExists("psql") {
		output.WriteString("=== PostgreSQL Status ===\n")
		if pgVersion := system.RunCommandWithTimeout("psql", []string{"--version"}, 5*time.Second); pgVersion != "" {
			output.WriteString(pgVersion)
			output.WriteString("\n")
		}
		
		// Check if PostgreSQL is running
		if system.CommandExists("pg_isready") {
			if pgReady := system.RunCommandWithTimeout("pg_isready", []string{}, 5*time.Second); pgReady != "" {
				output.WriteString("PostgreSQL Ready Status: ")
				output.WriteString(pgReady)
				output.WriteString("\n")
			}
		}
		
		// Try to list databases (might fail due to permissions)
		if pgDbs := system.RunCommandWithTimeout("psql", 
			[]string{"-U", "postgres", "-c", "\\l", "-t"}, 5*time.Second); pgDbs != "" {
			output.WriteString("\nPostgreSQL Databases:\n")
			output.WriteString(pgDbs)
			output.WriteString("\n")
		}
	} else {
		logger.Debug("PostgreSQL not found")
	}
	
	// MySQL/MariaDB
	if system.CommandExists("mysql") {
		output.WriteString("\n=== MySQL/MariaDB Status ===\n")
		if mysqlVersion := system.RunCommandWithTimeout("mysql", []string{"--version"}, 5*time.Second); mysqlVersion != "" {
			output.WriteString(mysqlVersion)
			output.WriteString("\n")
		}
		
		// Check MySQL status
		if mysqlStatus := system.RunCommandWithTimeout("mysqladmin", 
			[]string{"ping"}, 5*time.Second); mysqlStatus != "" {
			output.WriteString("MySQL Status: ")
			output.WriteString(mysqlStatus)
			output.WriteString("\n")
		}
	} else {
		logger.Debug("MySQL/MariaDB not found")
	}
	
	// MongoDB
	if system.CommandExists("mongosh") || system.CommandExists("mongo") {
		output.WriteString("\n=== MongoDB Status ===\n")
		mongoCmd := "mongosh"
		if !system.CommandExists("mongosh") {
			mongoCmd = "mongo"
		}
		
		if mongoVersion := system.RunCommandWithTimeout(mongoCmd, []string{"--version"}, 5*time.Second); mongoVersion != "" {
			output.WriteString(mongoVersion)
			output.WriteString("\n")
		}
	} else {
		logger.Debug("MongoDB not found")
	}
	
	// SQLite databases
	output.WriteString("\n=== SQLite Databases ===\n")
	sqlitePaths := []string{
		"/var/lib",
		"/opt",
		"/usr/local",
		system.GetHomeDir(),
	}
	
	foundSqlite := false
	for _, basePath := range sqlitePaths {
		if system.DirExists(basePath) {
			if findOutput := system.RunCommandWithTimeout("find", 
				[]string{basePath, "-name", "*.db", "-o", "-name", "*.sqlite", "-o", "-name", "*.sqlite3", 
					"-type", "f", "-size", "+1k", "-print", "-quit"}, 2*time.Second); findOutput != "" {
				output.WriteString(fmt.Sprintf("Found SQLite databases in %s\n", basePath))
				foundSqlite = true
			}
		}
	}
	
	if !foundSqlite {
		output.WriteString("No SQLite databases found in common locations\n")
	}
	
	// EVALUATE - Write results
	if err := os.WriteFile(outputFile, []byte(output.String()), 0644); err != nil {
		return fmt.Errorf("failed to write database diagnostics: %w", err)
	}
	
	logger.Info("Database diagnostics completed",
		zap.String("output_file", outputFile))
	
	return nil
}