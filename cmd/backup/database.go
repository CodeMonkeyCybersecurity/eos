// cmd/backup/database.go

package backup

import (
	"fmt"
	"strconv"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/database_management"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// databaseCmd handles database backup operations
var databaseCmd = &cobra.Command{
	Use:   "database",
	Short: "Database backup and restore operations",
	Long: `Manage database backups and restores for PostgreSQL, MySQL, MongoDB, and Redis.

Features:
  - Support for PostgreSQL, MySQL, MongoDB, and Redis
  - Vault integration for secure credential management
  - Compression and integrity checking
  - Schema and data filtering options
  - Backup verification and validation

Examples:
  # Create PostgreSQL backup
  eos backup database create --type postgresql --host localhost --database mydb --username myuser

  # Create MySQL backup with compression
  eos backup database create --type mysql --host localhost --database mydb --compression gzip

  # Restore PostgreSQL backup
  eos backup database restore --type postgresql --backup-path /var/backups/mydb_20240101.sql

  # Verify backup integrity
  eos backup database verify --backup-path /var/backups/mydb_20240101.sql

  # List all backups in directory
  eos backup database list --backup-dir /var/backups`,
}

// databaseCreateCmd creates database backups
var databaseCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a database backup",
	Long:  `Create a backup of a PostgreSQL, MySQL, MongoDB, or Redis database.`,
	RunE:  eos_cli.Wrap(runDatabaseCreate),
}

// databaseRestoreCmd restores databases from backups
var databaseRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore database from backup",
	Long:  `Restore a database from a previously created backup file.`,
	RunE:  eos_cli.Wrap(runDatabaseRestore),
}

// databaseVerifyCmd verifies backup integrity
var databaseVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify database backup integrity",
	Long:  `Verify the integrity and validity of a database backup file.`,
	RunE:  eos_cli.Wrap(runDatabaseVerify),
}

// databaseListCmd lists available backups
var databaseListCmd = &cobra.Command{
	Use:   "list",
	Short: "List database backups",
	Long:  `List all database backup files in a specified directory.`,
	RunE:  eos_cli.Wrap(runDatabaseList),
}

func init() {
	// Add database subcommands
	databaseCmd.AddCommand(databaseCreateCmd)
	databaseCmd.AddCommand(databaseRestoreCmd)
	databaseCmd.AddCommand(databaseVerifyCmd)
	databaseCmd.AddCommand(databaseListCmd)

	// Add database command to backup
	BackupCmd.AddCommand(databaseCmd)

	// Create command flags
	databaseCreateCmd.Flags().String("type", "", "Database type (postgresql, mysql, mongodb, redis) (required)")
	databaseCreateCmd.Flags().String("host", "localhost", "Database host")
	databaseCreateCmd.Flags().String("port", "", "Database port (prompted if not provided)")
	databaseCreateCmd.Flags().String("database", "", "Database name (prompted if not provided)")
	databaseCreateCmd.Flags().String("username", "", "Database username (prompted if not provided)")
	databaseCreateCmd.Flags().String("password", "", "Database password (prompted securely if not provided)")
	databaseCreateCmd.Flags().String("backup-dir", "/var/backups/databases", "Backup directory")
	databaseCreateCmd.Flags().String("backup-name", "", "Custom backup name (auto-generated if not provided)")
	databaseCreateCmd.Flags().String("compression", "gzip", "Compression type (none, gzip)")
	databaseCreateCmd.Flags().Bool("include-schema", true, "Include database schema")
	databaseCreateCmd.Flags().Bool("include-data", true, "Include database data")
	databaseCreateCmd.Flags().Bool("include-triggers", true, "Include triggers (MySQL only)")
	databaseCreateCmd.Flags().Bool("include-routines", true, "Include routines (MySQL only)")
	databaseCreateCmd.Flags().StringSlice("exclude-tables", []string{}, "Tables to exclude from backup")
	databaseCreateCmd.Flags().StringSlice("include-tables", []string{}, "Tables to include in backup (all if empty)")
	databaseCreateCmd.Flags().Bool("use-vault-creds", false, "Load credentials from Vault")
	databaseCreateCmd.Flags().String("vault-cred-path", "", "Vault path for credentials (required if using Vault)")
	databaseCreateCmd.Flags().Duration("timeout", 30*time.Minute, "Backup operation timeout")

	// Restore command flags
	databaseRestoreCmd.Flags().String("type", "", "Database type (postgresql, mysql, mongodb, redis) (required)")
	databaseRestoreCmd.Flags().String("host", "localhost", "Database host")
	databaseRestoreCmd.Flags().String("port", "", "Database port (prompted if not provided)")
	databaseRestoreCmd.Flags().String("database", "", "Database name (prompted if not provided)")
	databaseRestoreCmd.Flags().String("username", "", "Database username (prompted if not provided)")
	databaseRestoreCmd.Flags().String("password", "", "Database password (prompted securely if not provided)")
	databaseRestoreCmd.Flags().String("backup-path", "", "Path to backup file (prompted if not provided)")
	databaseRestoreCmd.Flags().Bool("use-vault-creds", false, "Load credentials from Vault")
	databaseRestoreCmd.Flags().String("vault-cred-path", "", "Vault path for credentials (required if using Vault)")
	databaseRestoreCmd.Flags().Bool("force", false, "Force restore without confirmation")

	// Verify command flags
	databaseVerifyCmd.Flags().String("backup-path", "", "Path to backup file (prompted if not provided)")
	databaseVerifyCmd.Flags().String("type", "", "Database type (auto-detected if not provided)")

	// List command flags
	databaseListCmd.Flags().String("backup-dir", "/var/backups/databases", "Backup directory to scan")
	databaseListCmd.Flags().String("type", "", "Filter by database type")
	databaseListCmd.Flags().Bool("detailed", false, "Show detailed backup information")
}

func runDatabaseCreate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get database type (required)
	dbType, _ := cmd.Flags().GetString("type")
	if dbType == "" {
		logger.Info("terminal prompt: Please enter database type")
		var err error
		dbType, err = eos_io.PromptInput(rc, "Database type (postgresql, mysql, mongodb, redis): ", "database_type")
		if err != nil {
			return fmt.Errorf("failed to read database type: %w", err)
		}
	}

	// Validate database type
	var databaseType database_management.DatabaseType
	switch dbType {
	case "postgresql", "postgres":
		databaseType = database_management.DatabaseTypePostgreSQL
	case "mysql":
		databaseType = database_management.DatabaseTypeMySQL
	case "mongodb", "mongo":
		databaseType = database_management.DatabaseTypeMongoDB
	case "redis":
		databaseType = database_management.DatabaseTypeRedis
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	// Get connection details
	host, _ := cmd.Flags().GetString("host")
	portStr, _ := cmd.Flags().GetString("port")
	database, _ := cmd.Flags().GetString("database")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")

	// Prompt for missing required fields
	if database == "" {
		logger.Info("terminal prompt: Please enter database name")
		var err error
		database, err = eos_io.PromptInput(rc, "Database name: ", "database_name")
		if err != nil {
			return fmt.Errorf("failed to read database name: %w", err)
		}
	}

	if username == "" && databaseType != database_management.DatabaseTypeRedis {
		logger.Info("terminal prompt: Please enter username")
		var err error
		username, err = eos_io.PromptInput(rc, "Username: ", "username")
		if err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}
	}

	if password == "" && databaseType != database_management.DatabaseTypeRedis {
		logger.Info("terminal prompt: Please enter password securely")
		var err error
		password, err = eos_io.PromptSecurePassword(rc, "Password: ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}

	// Set default ports if not provided
	var port int
	if portStr == "" {
		switch databaseType {
		case database_management.DatabaseTypePostgreSQL:
			port = 5432
		case database_management.DatabaseTypeMySQL:
			port = 3306
		case database_management.DatabaseTypeMongoDB:
			port = 27017
		case database_management.DatabaseTypeRedis:
			port = 6379
		}
	} else {
		var err error
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port number: %s", portStr)
		}
	}

	// Get backup configuration
	backupDir, _ := cmd.Flags().GetString("backup-dir")
	backupName, _ := cmd.Flags().GetString("backup-name")
	compression, _ := cmd.Flags().GetString("compression")
	includeSchema, _ := cmd.Flags().GetBool("include-schema")
	includeData, _ := cmd.Flags().GetBool("include-data")
	includeTriggers, _ := cmd.Flags().GetBool("include-triggers")
	includeRoutines, _ := cmd.Flags().GetBool("include-routines")
	excludeTables, _ := cmd.Flags().GetStringSlice("exclude-tables")
	includeTables, _ := cmd.Flags().GetStringSlice("include-tables")
	useVaultCreds, _ := cmd.Flags().GetBool("use-vault-creds")
	vaultCredPath, _ := cmd.Flags().GetString("vault-cred-path")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	// Create database configuration
	dbConfig := &database_management.DatabaseConfig{
		Type:     databaseType,
		Host:     host,
		Port:     port,
		Database: database,
		Username: username,
		Password: password,
	}

	// Create backup configuration
	backupConfig := &database_management.DatabaseBackupConfig{
		DatabaseConfig:  dbConfig,
		BackupDir:       backupDir,
		BackupName:      backupName,
		Compression:     compression,
		IncludeSchema:   includeSchema,
		IncludeData:     includeData,
		IncludeTriggers: includeTriggers,
		IncludeRoutines: includeRoutines,
		ExcludeTables:   excludeTables,
		IncludeTables:   includeTables,
		Timeout:         timeout,
		UseVaultCreds:   useVaultCreds,
		VaultCredPath:   vaultCredPath,
	}

	// Create backup manager
	manager := database_management.NewDatabaseBackupManager(backupConfig, otelzap.Ctx(rc.Ctx))

	// Create backup
	result, err := manager.CreateBackup(rc)
	if err != nil {
		return fmt.Errorf("database backup failed: %w", err)
	}

	logger.Info("Database backup completed successfully",
		zap.String("database_type", string(databaseType)),
		zap.String("database", database),
		zap.String("backup_path", result.BackupPath),
		zap.Int64("backup_size", result.BackupSize),
		zap.Duration("duration", result.Duration),
		zap.Bool("compressed", result.Compressed))

	return nil
}

func runDatabaseRestore(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get database type (required)
	dbType, _ := cmd.Flags().GetString("type")
	if dbType == "" {
		logger.Info("terminal prompt: Please enter database type")
		var err error
		dbType, err = eos_io.PromptInput(rc, "Database type (postgresql, mysql, mongodb, redis): ", "database_type")
		if err != nil {
			return fmt.Errorf("failed to read database type: %w", err)
		}
	}

	// Validate database type
	var databaseType database_management.DatabaseType
	switch dbType {
	case "postgresql", "postgres":
		databaseType = database_management.DatabaseTypePostgreSQL
	case "mysql":
		databaseType = database_management.DatabaseTypeMySQL
	case "mongodb", "mongo":
		databaseType = database_management.DatabaseTypeMongoDB
	case "redis":
		databaseType = database_management.DatabaseTypeRedis
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	// Get backup path
	backupPath, _ := cmd.Flags().GetString("backup-path")
	if backupPath == "" {
		logger.Info("terminal prompt: Please enter backup file path")
		var err error
		backupPath, err = eos_io.PromptInput(rc, "Backup file path: ", "backup_path")
		if err != nil {
			return fmt.Errorf("failed to read backup path: %w", err)
		}
	}

	// Get connection details
	host, _ := cmd.Flags().GetString("host")
	portStr, _ := cmd.Flags().GetString("port")
	database, _ := cmd.Flags().GetString("database")
	username, _ := cmd.Flags().GetString("username")
	password, _ := cmd.Flags().GetString("password")

	// Prompt for missing required fields
	if database == "" {
		logger.Info("terminal prompt: Please enter database name")
		var err error
		database, err = eos_io.PromptInput(rc, "Database name: ", "database_name")
		if err != nil {
			return fmt.Errorf("failed to read database name: %w", err)
		}
	}

	if username == "" && databaseType != database_management.DatabaseTypeRedis {
		logger.Info("terminal prompt: Please enter username")
		var err error
		username, err = eos_io.PromptInput(rc, "Username: ", "username")
		if err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}
	}

	if password == "" && databaseType != database_management.DatabaseTypeRedis {
		logger.Info("terminal prompt: Please enter password securely")
		var err error
		password, err = eos_io.PromptSecurePassword(rc, "Password: ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}

	// Set default ports if not provided
	var port int
	if portStr == "" {
		switch databaseType {
		case database_management.DatabaseTypePostgreSQL:
			port = 5432
		case database_management.DatabaseTypeMySQL:
			port = 3306
		case database_management.DatabaseTypeMongoDB:
			port = 27017
		case database_management.DatabaseTypeRedis:
			port = 6379
		}
	} else {
		var err error
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port number: %s", portStr)
		}
	}

	force, _ := cmd.Flags().GetBool("force")
	useVaultCreds, _ := cmd.Flags().GetBool("use-vault-creds")
	vaultCredPath, _ := cmd.Flags().GetString("vault-cred-path")

	// Confirm restore unless force flag is used
	if !force {
		logger.Info("terminal prompt: Confirm database restore")
		confirmation, err := eos_io.PromptInput(rc, fmt.Sprintf("Restore database '%s' from backup? This will overwrite existing data. (y/N): ", database), "confirmation")
		if err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		if confirmation != "y" && confirmation != "Y" && confirmation != "yes" {
			logger.Info("Database restore cancelled")
			return nil
		}
	}

	// Create database configuration
	dbConfig := &database_management.DatabaseConfig{
		Type:     databaseType,
		Host:     host,
		Port:     port,
		Database: database,
		Username: username,
		Password: password,
	}

	// Create backup configuration
	backupConfig := &database_management.DatabaseBackupConfig{
		DatabaseConfig: dbConfig,
		UseVaultCreds:  useVaultCreds,
		VaultCredPath:  vaultCredPath,
	}

	// Create backup manager
	manager := database_management.NewDatabaseBackupManager(backupConfig, otelzap.Ctx(rc.Ctx))

	// Restore backup
	err := manager.RestoreBackup(rc, backupPath)
	if err != nil {
		return fmt.Errorf("database restore failed: %w", err)
	}

	logger.Info("Database restore completed successfully",
		zap.String("database_type", string(databaseType)),
		zap.String("database", database),
		zap.String("backup_path", backupPath))

	return nil
}

func runDatabaseVerify(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get backup path
	backupPath, _ := cmd.Flags().GetString("backup-path")
	if backupPath == "" {
		logger.Info("terminal prompt: Please enter backup file path")
		var err error
		backupPath, err = eos_io.PromptInput(rc, "Backup file path: ", "backup_path")
		if err != nil {
			return fmt.Errorf("failed to read backup path: %w", err)
		}
	}

	// Get database type (can be auto-detected)
	dbType, _ := cmd.Flags().GetString("type")
	if dbType == "" {
		// Try to auto-detect from filename or prompt user
		logger.Info("terminal prompt: Please enter database type for verification")
		var err error
		dbType, err = eos_io.PromptInput(rc, "Database type (postgresql, mysql, mongodb, redis): ", "database_type")
		if err != nil {
			return fmt.Errorf("failed to read database type: %w", err)
		}
	}

	// Validate database type
	var databaseType database_management.DatabaseType
	switch dbType {
	case "postgresql", "postgres":
		databaseType = database_management.DatabaseTypePostgreSQL
	case "mysql":
		databaseType = database_management.DatabaseTypeMySQL
	case "mongodb", "mongo":
		databaseType = database_management.DatabaseTypeMongoDB
	case "redis":
		databaseType = database_management.DatabaseTypeRedis
	default:
		return fmt.Errorf("unsupported database type: %s", dbType)
	}

	// Create minimal database configuration for verification
	dbConfig := &database_management.DatabaseConfig{
		Type: databaseType,
	}

	// Create backup configuration
	backupConfig := &database_management.DatabaseBackupConfig{
		DatabaseConfig: dbConfig,
	}

	// Create backup manager
	manager := database_management.NewDatabaseBackupManager(backupConfig, otelzap.Ctx(rc.Ctx))

	// Verify backup
	err := manager.VerifyBackup(rc, backupPath)
	if err != nil {
		return fmt.Errorf("backup verification failed: %w", err)
	}

	logger.Info("Database backup verified successfully",
		zap.String("database_type", string(databaseType)),
		zap.String("backup_path", backupPath))

	return nil
}

func runDatabaseList(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	backupDir, _ := cmd.Flags().GetString("backup-dir")
	typeFilter, _ := cmd.Flags().GetString("type")
	detailed, _ := cmd.Flags().GetBool("detailed")

	logger.Info("Listing database backups",
		zap.String("backup_dir", backupDir),
		zap.String("type_filter", typeFilter),
		zap.Bool("detailed", detailed))

	// This would need to be implemented as a helper function
	// For now, we'll provide basic directory listing functionality
	logger.Info("Database backup listing functionality not yet fully implemented")
	logger.Info("Please check the backup directory manually",
		zap.String("backup_dir", backupDir))

	return nil
}
