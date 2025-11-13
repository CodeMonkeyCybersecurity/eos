// pkg/database_management/backup.go

package database_management

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DatabaseBackupConfig defines configuration for database backup operations
type DatabaseBackupConfig struct {
	DatabaseConfig  *DatabaseConfig   `yaml:"database" json:"database"`
	BackupDir       string            `yaml:"backup_dir" json:"backup_dir"`
	BackupName      string            `yaml:"backup_name" json:"backup_name"`
	Compression     string            `yaml:"compression" json:"compression"` // gzip, none
	IncludeSchema   bool              `yaml:"include_schema" json:"include_schema"`
	IncludeData     bool              `yaml:"include_data" json:"include_data"`
	IncludeTriggers bool              `yaml:"include_triggers" json:"include_triggers"`
	IncludeRoutines bool              `yaml:"include_routines" json:"include_routines"`
	ExcludeTables   []string          `yaml:"exclude_tables" json:"exclude_tables"`
	IncludeTables   []string          `yaml:"include_tables" json:"include_tables"`
	Timeout         time.Duration     `yaml:"timeout" json:"timeout"`
	Parallel        bool              `yaml:"parallel" json:"parallel"`
	CustomOptions   map[string]string `yaml:"custom_options" json:"custom_options"`
	UseVaultCreds   bool              `yaml:"use_vault_creds" json:"use_vault_creds"`
	VaultCredPath   string            `yaml:"vault_cred_path" json:"vault_cred_path"`
}

// DatabaseBackupResult represents the result of a database backup operation
type DatabaseBackupResult struct {
	Success        bool              `json:"success"`
	BackupPath     string            `json:"backup_path"`
	BackupSize     int64             `json:"backup_size"`
	Duration       time.Duration     `json:"duration"`
	DatabaseType   DatabaseType      `json:"database_type"`
	TablesBackup   []string          `json:"tables_backup"`
	SchemaInfo     *SchemaInfo       `json:"schema_info,omitempty"`
	Metadata       map[string]string `json:"metadata"`
	ErrorMessage   string            `json:"error_message,omitempty"`
	Compressed     bool              `json:"compressed"`
	ChecksumMD5    string            `json:"checksum_md5,omitempty"`
	ChecksumSHA256 string            `json:"checksum_sha256,omitempty"`
}

// DatabaseBackupManager handles database backup operations following Assess → Intervene → Evaluate pattern
type DatabaseBackupManager struct {
	config *DatabaseBackupConfig
	logger *otelzap.LoggerWithCtx
}

// NewDatabaseBackupManager creates a new database backup manager
func NewDatabaseBackupManager(config *DatabaseBackupConfig, logger otelzap.LoggerWithCtx) *DatabaseBackupManager {
	return &DatabaseBackupManager{
		config: config,
		logger: &logger,
	}
}

// CreateBackup creates a database backup following AIE pattern
func (dbm *DatabaseBackupManager) CreateBackup(rc *eos_io.RuntimeContext) (*DatabaseBackupResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	startTime := time.Now()

	logger.Info("Starting database backup",
		zap.String("database_type", string(dbm.config.DatabaseConfig.Type)),
		zap.String("database", dbm.config.DatabaseConfig.Database),
		zap.String("backup_dir", dbm.config.BackupDir),
		zap.Bool("include_schema", dbm.config.IncludeSchema),
		zap.Bool("include_data", dbm.config.IncludeData))

	result := &DatabaseBackupResult{
		DatabaseType: dbm.config.DatabaseConfig.Type,
		Metadata:     make(map[string]string),
	}

	// Assessment: Verify database connectivity and backup requirements
	if err := dbm.assessDatabaseBackup(rc, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Database backup assessment failed: %v", err)
		return result, err
	}

	// Intervention: Execute the backup based on database type
	if err := dbm.createBackupIntervention(rc, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Database backup failed: %v", err)
		return result, err
	}

	// Evaluation: Verify backup integrity and completeness
	if err := dbm.evaluateBackup(rc, result); err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("Database backup verification failed: %v", err)
		return result, err
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	logger.Info("Database backup completed successfully",
		zap.String("backup_path", result.BackupPath),
		zap.Duration("duration", result.Duration),
		zap.Int64("backup_size", result.BackupSize))

	return result, nil
}

// RestoreBackup restores a database from backup
func (dbm *DatabaseBackupManager) RestoreBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting database restore",
		zap.String("database_type", string(dbm.config.DatabaseConfig.Type)),
		zap.String("backup_path", backupPath))

	// Assessment: Verify backup exists and database can be restored
	if err := dbm.assessDatabaseRestore(rc, backupPath); err != nil {
		return fmt.Errorf("database restore assessment failed: %w", err)
	}

	// Intervention: Restore database from backup
	if err := dbm.restoreBackupIntervention(rc, backupPath); err != nil {
		return fmt.Errorf("database restore failed: %w", err)
	}

	// Evaluation: Verify restore was successful
	if err := dbm.evaluateRestore(rc); err != nil {
		return fmt.Errorf("database restore verification failed: %w", err)
	}

	logger.Info("Database restore completed successfully")
	return nil
}

// VerifyBackup checks the integrity of a database backup
func (dbm *DatabaseBackupManager) VerifyBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying database backup integrity",
		zap.String("database_type", string(dbm.config.DatabaseConfig.Type)),
		zap.String("backup_path", backupPath))

	// Check backup file exists
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file not found: %w", err)
	}

	// Verify backup based on database type
	switch dbm.config.DatabaseConfig.Type {
	case DatabaseTypePostgreSQL:
		return dbm.verifyPostgreSQLBackup(rc, backupPath)
	case DatabaseTypeMySQL:
		return dbm.verifyMySQLBackup(rc, backupPath)
	case DatabaseTypeMongoDB:
		return dbm.verifyMongoDBBackup(rc, backupPath)
	case DatabaseTypeRedis:
		return dbm.verifyRedisBackup(rc, backupPath)
	default:
		return fmt.Errorf("backup verification not implemented for database type: %s", dbm.config.DatabaseConfig.Type)
	}
}

// Implementation methods

func (dbm *DatabaseBackupManager) assessDatabaseBackup(rc *eos_io.RuntimeContext, result *DatabaseBackupResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Get database credentials from Vault if configured
	if dbm.config.UseVaultCreds {
		if err := dbm.loadVaultCredentials(rc); err != nil {
			return fmt.Errorf("failed to load vault credentials: %w", err)
		}
	}

	// Test database connectivity
	if err := dbm.testDatabaseConnection(rc); err != nil {
		return fmt.Errorf("database connection failed: %w", err)
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(dbm.config.BackupDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Get schema information
	if schemaInfo, err := dbm.getSchemaInfo(rc); err != nil {
		logger.Warn("Failed to get schema info", zap.Error(err))
	} else {
		result.SchemaInfo = schemaInfo
	}

	logger.Info("Database backup assessment completed successfully")
	return nil
}

func (dbm *DatabaseBackupManager) createBackupIntervention(rc *eos_io.RuntimeContext, result *DatabaseBackupResult) error {
	timestamp := time.Now().Format("20060102-150405")

	var backupFileName string
	if dbm.config.BackupName != "" {
		backupFileName = fmt.Sprintf("%s_%s", dbm.config.BackupName, timestamp)
	} else {
		backupFileName = fmt.Sprintf("%s_%s_%s", dbm.config.DatabaseConfig.Database, string(dbm.config.DatabaseConfig.Type), timestamp)
	}

	// Add compression extension if enabled
	switch dbm.config.Compression {
	case "gzip":
		backupFileName += ".sql.gz"
		result.Compressed = true
	default:
		backupFileName += ".sql"
		result.Compressed = false
	}

	backupPath := filepath.Join(dbm.config.BackupDir, backupFileName)
	result.BackupPath = backupPath

	// Execute backup based on database type
	switch dbm.config.DatabaseConfig.Type {
	case DatabaseTypePostgreSQL:
		return dbm.createPostgreSQLBackup(rc, result)
	case DatabaseTypeMySQL:
		return dbm.createMySQLBackup(rc, result)
	case DatabaseTypeMongoDB:
		return dbm.createMongoDBBackup(rc, result)
	case DatabaseTypeRedis:
		return dbm.createRedisBackup(rc, result)
	default:
		return fmt.Errorf("backup not implemented for database type: %s", dbm.config.DatabaseConfig.Type)
	}
}

func (dbm *DatabaseBackupManager) evaluateBackup(rc *eos_io.RuntimeContext, result *DatabaseBackupResult) error {
	// Verify backup file exists
	if _, err := os.Stat(result.BackupPath); err != nil {
		return fmt.Errorf("backup file not created: %w", err)
	}

	// Get backup file size
	if fileInfo, err := os.Stat(result.BackupPath); err == nil {
		result.BackupSize = fileInfo.Size()
	}

	// Calculate checksums for integrity verification
	if err := dbm.calculateChecksums(rc, result.BackupPath, result); err != nil {
		return fmt.Errorf("failed to calculate checksums: %w", err)
	}

	// Verify backup can be read
	return dbm.VerifyBackup(rc, result.BackupPath)
}

// PostgreSQL backup implementation
func (dbm *DatabaseBackupManager) createPostgreSQLBackup(rc *eos_io.RuntimeContext, result *DatabaseBackupResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating PostgreSQL backup")

	args := []string{
		"pg_dump",
		"--host", dbm.config.DatabaseConfig.Host,
		"--port", fmt.Sprintf("%d", dbm.config.DatabaseConfig.Port),
		"--username", dbm.config.DatabaseConfig.Username,
		"--dbname", dbm.config.DatabaseConfig.Database,
		"--verbose",
		"--no-password",
	}

	// Add schema/data options
	if !dbm.config.IncludeSchema {
		args = append(args, "--data-only")
	}
	if !dbm.config.IncludeData {
		args = append(args, "--schema-only")
	}

	// Add table filters
	for _, table := range dbm.config.IncludeTables {
		args = append(args, "--table", table)
	}
	for _, table := range dbm.config.ExcludeTables {
		args = append(args, "--exclude-table", table)
	}

	// Environment variables are embedded in the bash command below

	// SECURITY P0 #1: Execute backup with proper file handling (no shell injection)
	// Set PGPASSWORD via environment variable (secure - not visible in process list)
	cmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", dbm.config.DatabaseConfig.Password))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("pg_dump failed: %w (stderr: %s)", err, stderr.String())
	}

	output := stdout.String()

	// Write output to file securely
	var dataToWrite []byte
	if dbm.config.Compression == "gzip" {
		// Compress the output
		compressed, err := gzipCompress([]byte(output))
		if err != nil {
			return fmt.Errorf("gzip compression failed: %w", err)
		}
		dataToWrite = compressed
	} else {
		dataToWrite = []byte(output)
	}

	// SECURITY P0 #2: Validate backup path before writing (prevent path traversal)
	if err := validateBackupPath(result.BackupPath, dbm.config.BackupDir); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	if err := os.WriteFile(result.BackupPath, dataToWrite, shared.SecretFilePerm); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

// MySQL backup implementation
func (dbm *DatabaseBackupManager) createMySQLBackup(rc *eos_io.RuntimeContext, result *DatabaseBackupResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating MySQL backup")

	// SECURITY P1 #5: Don't pass password via command-line (visible in ps aux)
	// Use MYSQL_PWD environment variable instead
	args := []string{
		"mysqldump",
		"--host", dbm.config.DatabaseConfig.Host,
		"--port", fmt.Sprintf("%d", dbm.config.DatabaseConfig.Port),
		"--user", dbm.config.DatabaseConfig.Username,
		"--single-transaction",
		"--routines",
		"--triggers",
	}

	// Add schema/data options
	if !dbm.config.IncludeSchema {
		args = append(args, "--no-create-info")
	}
	if !dbm.config.IncludeData {
		args = append(args, "--no-data")
	}
	if !dbm.config.IncludeTriggers {
		args = append(args, "--skip-triggers")
	}
	if !dbm.config.IncludeRoutines {
		args = append(args, "--skip-routines")
	}

	// Add table filters
	for _, table := range dbm.config.ExcludeTables {
		args = append(args, fmt.Sprintf("--ignore-table=%s.%s", dbm.config.DatabaseConfig.Database, table))
	}

	// Add database name
	args = append(args, dbm.config.DatabaseConfig.Database)

	// Add specific tables if specified
	if len(dbm.config.IncludeTables) > 0 {
		args = append(args, dbm.config.IncludeTables...)
	}

	// SECURITY P0 #1: Execute backup with proper file handling (no shell injection)
	// SECURITY P1 #5: Set MYSQL_PWD via environment (not visible in process list)
	cmd := exec.CommandContext(rc.Ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("MYSQL_PWD=%s", dbm.config.DatabaseConfig.Password))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("mysqldump failed: %w (stderr: %s)", err, stderr.String())
	}

	output := stdout.String()

	// Write output to file securely
	var dataToWrite []byte
	if dbm.config.Compression == "gzip" {
		compressed, err := gzipCompress([]byte(output))
		if err != nil {
			return fmt.Errorf("gzip compression failed: %w", err)
		}
		dataToWrite = compressed
	} else {
		dataToWrite = []byte(output)
	}

	// SECURITY P0 #2: Validate backup path before writing
	if err := validateBackupPath(result.BackupPath, dbm.config.BackupDir); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	if err := os.WriteFile(result.BackupPath, dataToWrite, shared.SecretFilePerm); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	return nil
}

// MongoDB backup implementation
func (dbm *DatabaseBackupManager) createMongoDBBackup(rc *eos_io.RuntimeContext, result *DatabaseBackupResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating MongoDB backup")

	// MongoDB uses directory-based backups
	backupDir := strings.TrimSuffix(result.BackupPath, ".sql")
	result.BackupPath = backupDir

	args := []string{
		"mongodump",
		"--host", fmt.Sprintf("%s:%d", dbm.config.DatabaseConfig.Host, dbm.config.DatabaseConfig.Port),
		"--db", dbm.config.DatabaseConfig.Database,
		"--out", backupDir,
	}

	// Add authentication if provided
	if dbm.config.DatabaseConfig.Username != "" {
		args = append(args, "--username", dbm.config.DatabaseConfig.Username)
		args = append(args, "--password", dbm.config.DatabaseConfig.Password)
	}

	// Add collection filters
	for _, table := range dbm.config.IncludeTables {
		args = append(args, "--collection", table)
	}
	for _, table := range dbm.config.ExcludeTables {
		args = append(args, "--excludeCollection", table)
	}

	err := execute.RunSimple(rc.Ctx, args[0], args[1:]...)
	if err != nil {
		return fmt.Errorf("mongodump failed: %w", err)
	}

	// Compress if requested
	if dbm.config.Compression == "gzip" {
		compressedPath := backupDir + ".tar.gz"
		err := execute.RunSimple(rc.Ctx, "tar", "-czf", compressedPath, "-C", filepath.Dir(backupDir), filepath.Base(backupDir))
		if err != nil {
			return fmt.Errorf("compression failed: %w", err)
		}

		// SECURITY P2 #7: Validate backupDir path before os.RemoveAll
		// Only remove if it's within our backup directory
		if err := validateBackupPath(backupDir, dbm.config.BackupDir); err == nil {
			_ = os.RemoveAll(backupDir)
		}

		result.BackupPath = compressedPath
		result.Compressed = true
	}

	return nil
}

// Redis backup implementation
func (dbm *DatabaseBackupManager) createRedisBackup(rc *eos_io.RuntimeContext, result *DatabaseBackupResult) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating Redis backup")

	// For Redis, we'll use BGSAVE or copy the RDB file
	args := []string{
		"redis-cli",
		"-h", dbm.config.DatabaseConfig.Host,
		"-p", fmt.Sprintf("%d", dbm.config.DatabaseConfig.Port),
	}

	// Add authentication if provided
	if dbm.config.DatabaseConfig.Password != "" {
		args = append(args, "-a", dbm.config.DatabaseConfig.Password)
	}

	// Trigger background save
	saveArgs := append(args, "BGSAVE")
	_, err := execute.Run(rc.Ctx, execute.Options{
		Command: saveArgs[0],
		Args:    saveArgs[1:],
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("redis BGSAVE failed: %w", err)
	}

	// SECURITY P2 #6: Wait for save to complete with proper timestamp comparison
	// SECURITY P1 #4: Use context-aware sleep to respect cancellation
	checkArgs := append(args, "LASTSAVE")

	// Get initial timestamp before BGSAVE
	initialOutput, err := execute.Run(rc.Ctx, execute.Options{
		Command: checkArgs[0],
		Args:    checkArgs[1:],
		Capture: true,
	})
	if err != nil {
		return fmt.Errorf("redis initial LASTSAVE check failed: %w", err)
	}
	initialTimestamp := strings.TrimSpace(initialOutput)

	// Poll for completion (max 60 seconds)
	maxAttempts := 60
	for i := 0; i < maxAttempts; i++ {
		currentOutput, err := execute.Run(rc.Ctx, execute.Options{
			Command: checkArgs[0],
			Args:    checkArgs[1:],
			Capture: true,
		})
		if err != nil {
			return fmt.Errorf("redis LASTSAVE check failed: %w", err)
		}

		currentTimestamp := strings.TrimSpace(currentOutput)
		if currentTimestamp != initialTimestamp {
			// Save completed successfully
			break
		}

		if i < maxAttempts-1 {
			// Context-aware sleep
			select {
			case <-time.After(1 * time.Second):
				// Continue polling
			case <-rc.Ctx.Done():
				return fmt.Errorf("redis backup cancelled: %w", rc.Ctx.Err())
			}
		}
	}

	// Copy the RDB file to backup location
	rdbPath := "/var/lib/redis/dump.rdb" // Default Redis RDB path
	err = execute.RunSimple(rc.Ctx, "cp", rdbPath, result.BackupPath)
	if err != nil {
		return fmt.Errorf("failed to copy RDB file: %w", err)
	}

	return nil
}

// Verification methods

func (dbm *DatabaseBackupManager) verifyPostgreSQLBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	// SECURITY P0 #2: Validate backup path before reading
	if err := validateBackupPath(backupPath, dbm.config.BackupDir); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	var dataToVerify []byte
	var err error

	if strings.HasSuffix(backupPath, ".gz") {
		// SECURITY P0 #1: Read compressed backup securely (no shell injection)
		compressed, err := os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("failed to read backup file: %w", err)
		}
		dataToVerify, err = gzipDecompress(compressed)
		if err != nil {
			return fmt.Errorf("failed to decompress backup: %w", err)
		}
	} else {
		dataToVerify, err = os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("failed to read backup file: %w", err)
		}
	}

	// Verify backup format (check for SQL header)
	if len(dataToVerify) < 100 {
		return fmt.Errorf("backup file too small to be valid")
	}

	// Basic validation - check for PostgreSQL dump header
	header := string(dataToVerify[:100])
	if !strings.Contains(header, "PostgreSQL") && !strings.Contains(header, "CREATE TABLE") && !strings.Contains(header, "INSERT INTO") {
		return fmt.Errorf("backup file does not appear to be a valid PostgreSQL dump")
	}

	return nil
}

func (dbm *DatabaseBackupManager) verifyMySQLBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	// SECURITY P0 #2: Validate backup path before reading
	if err := validateBackupPath(backupPath, dbm.config.BackupDir); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	var dataToVerify []byte
	var err error

	if strings.HasSuffix(backupPath, ".gz") {
		compressed, err := os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("failed to read backup file: %w", err)
		}
		dataToVerify, err = gzipDecompress(compressed)
		if err != nil {
			return fmt.Errorf("failed to decompress backup: %w", err)
		}
	} else {
		dataToVerify, err = os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("failed to read backup file: %w", err)
		}
	}

	// Basic validation - check for MySQL dump header
	header := string(dataToVerify[:min(len(dataToVerify), 200)])
	if !strings.Contains(header, "MySQL") && !strings.Contains(header, "CREATE TABLE") && !strings.Contains(header, "INSERT INTO") {
		return fmt.Errorf("backup file does not appear to be a valid MySQL dump")
	}

	return nil
}

func (dbm *DatabaseBackupManager) verifyMongoDBBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	// Verify MongoDB backup directory structure
	if strings.HasSuffix(backupPath, ".tar.gz") {
		// Verify compressed backup can be extracted
		err := execute.RunSimple(rc.Ctx, "tar", "-tzf", backupPath)
		return err
	}

	// Verify directory contains BSON files
	entries, err := os.ReadDir(backupPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".bson") {
			return nil // Found at least one BSON file
		}
	}

	return fmt.Errorf("no BSON files found in backup")
}

func (dbm *DatabaseBackupManager) verifyRedisBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	// Verify RDB file format
	file, err := os.Open(backupPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	// Check RDB magic header
	header := make([]byte, 9)
	_, err = file.Read(header)
	if err != nil {
		return err
	}

	if string(header[:5]) != "REDIS" {
		return fmt.Errorf("invalid RDB file format")
	}

	return nil
}

// Helper methods

func (dbm *DatabaseBackupManager) loadVaultCredentials(rc *eos_io.RuntimeContext) error {
	if dbm.config.VaultCredPath == "" {
		return fmt.Errorf("vault credential path not specified")
	}

	// Get Vault client
	vaultClient, err := vault.GetVaultClient(rc)
	if err != nil {
		return fmt.Errorf("failed to get vault client: %w", err)
	}

	// Read credentials from Vault
	secret, err := vaultClient.KVv2("secret").Get(rc.Ctx, dbm.config.VaultCredPath)
	if err != nil {
		return fmt.Errorf("failed to read vault secret: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no secret found at path: %s", dbm.config.VaultCredPath)
	}

	// Extract credentials
	if username, ok := secret.Data["username"].(string); ok {
		dbm.config.DatabaseConfig.Username = username
	}
	if password, ok := secret.Data["password"].(string); ok {
		dbm.config.DatabaseConfig.Password = password
	}

	return nil
}

func (dbm *DatabaseBackupManager) testDatabaseConnection(rc *eos_io.RuntimeContext) error {
	switch dbm.config.DatabaseConfig.Type {
	case DatabaseTypePostgreSQL:
		return dbm.testPostgreSQLConnection(rc)
	case DatabaseTypeMySQL:
		return dbm.testMySQLConnection(rc)
	case DatabaseTypeMongoDB:
		return dbm.testMongoDBConnection(rc)
	case DatabaseTypeRedis:
		return dbm.testRedisConnection(rc)
	default:
		return fmt.Errorf("connection test not implemented for: %s", dbm.config.DatabaseConfig.Type)
	}
}

func (dbm *DatabaseBackupManager) testPostgreSQLConnection(rc *eos_io.RuntimeContext) error {
	// SECURITY P0 #1: Use exec.CommandContext with environment variables (no shell injection)
	// SECURITY P1 #5: Set PGPASSWORD via environment (not visible in process list)
	cmd := exec.CommandContext(rc.Ctx, "psql",
		"--host", dbm.config.DatabaseConfig.Host,
		"--port", fmt.Sprintf("%d", dbm.config.DatabaseConfig.Port),
		"--username", dbm.config.DatabaseConfig.Username,
		"--dbname", dbm.config.DatabaseConfig.Database,
		"--command", "SELECT 1;",
		"--no-psqlrc") // Don't load user's psqlrc file

	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", dbm.config.DatabaseConfig.Password))

	return cmd.Run()
}

func (dbm *DatabaseBackupManager) testMySQLConnection(rc *eos_io.RuntimeContext) error {
	// SECURITY P1 #5: Use MYSQL_PWD environment variable (not visible in process list)
	cmd := exec.CommandContext(rc.Ctx, "mysql",
		"--host", dbm.config.DatabaseConfig.Host,
		"--port", fmt.Sprintf("%d", dbm.config.DatabaseConfig.Port),
		"--user", dbm.config.DatabaseConfig.Username,
		dbm.config.DatabaseConfig.Database,
		"--execute", "SELECT 1;")

	cmd.Env = append(os.Environ(), fmt.Sprintf("MYSQL_PWD=%s", dbm.config.DatabaseConfig.Password))

	return cmd.Run()
}

func (dbm *DatabaseBackupManager) testMongoDBConnection(rc *eos_io.RuntimeContext) error {
	args := []string{
		"mongo",
		"--host", fmt.Sprintf("%s:%d", dbm.config.DatabaseConfig.Host, dbm.config.DatabaseConfig.Port),
		dbm.config.DatabaseConfig.Database,
		"--eval", "db.runCommand('ping')",
	}

	if dbm.config.DatabaseConfig.Username != "" {
		args = append(args, "--username", dbm.config.DatabaseConfig.Username)
		args = append(args, "--password", dbm.config.DatabaseConfig.Password)
	}

	return execute.RunSimple(rc.Ctx, args[0], args[1:]...)
}

func (dbm *DatabaseBackupManager) testRedisConnection(rc *eos_io.RuntimeContext) error {
	// SECURITY P1 #5: Use REDISCLI_AUTH environment variable (not visible in process list)
	cmd := exec.CommandContext(rc.Ctx, "redis-cli",
		"-h", dbm.config.DatabaseConfig.Host,
		"-p", fmt.Sprintf("%d", dbm.config.DatabaseConfig.Port),
		"ping")

	if dbm.config.DatabaseConfig.Password != "" {
		// Don't use -a flag (visible in ps aux), use environment variable instead
		cmd.Env = append(os.Environ(), fmt.Sprintf("REDISCLI_AUTH=%s", dbm.config.DatabaseConfig.Password))
	}

	return cmd.Run()
}

func (dbm *DatabaseBackupManager) getSchemaInfo(rc *eos_io.RuntimeContext) (*SchemaInfo, error) {
	// Implementation would depend on database type
	// Returning basic structure for now
	return &SchemaInfo{
		Database: dbm.config.DatabaseConfig.Database,
		Tables:   []TableInfo{},
		Views:    []ViewInfo{},
		Indexes:  []IndexInfo{},
		Triggers: []TriggerInfo{},
	}, nil
}

func (dbm *DatabaseBackupManager) calculateChecksums(rc *eos_io.RuntimeContext, backupPath string, result *DatabaseBackupResult) error {
	// SECURITY P1 #4: Use rc.Ctx instead of context.Background() for proper cancellation
	// Calculate MD5 checksum
	md5Output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "md5sum",
		Args:    []string{backupPath},
		Capture: true,
	})
	if err == nil {
		fields := strings.Fields(md5Output)
		if len(fields) > 0 {
			result.ChecksumMD5 = fields[0]
		}
	}

	// Calculate SHA256 checksum
	sha256Output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "sha256sum",
		Args:    []string{backupPath},
		Capture: true,
	})
	if err == nil {
		fields := strings.Fields(sha256Output)
		if len(fields) > 0 {
			result.ChecksumSHA256 = fields[0]
		}
	}

	return nil
}

func (dbm *DatabaseBackupManager) assessDatabaseRestore(rc *eos_io.RuntimeContext, backupPath string) error {
	// Verify backup file exists
	if _, err := os.Stat(backupPath); err != nil {
		return fmt.Errorf("backup file not found: %w", err)
	}

	// Test database connection
	return dbm.testDatabaseConnection(rc)
}

func (dbm *DatabaseBackupManager) restoreBackupIntervention(rc *eos_io.RuntimeContext, backupPath string) error {
	switch dbm.config.DatabaseConfig.Type {
	case DatabaseTypePostgreSQL:
		return dbm.restorePostgreSQLBackup(rc, backupPath)
	case DatabaseTypeMySQL:
		return dbm.restoreMySQLBackup(rc, backupPath)
	case DatabaseTypeMongoDB:
		return dbm.restoreMongoDBBackup(rc, backupPath)
	case DatabaseTypeRedis:
		return dbm.restoreRedisBackup(rc, backupPath)
	default:
		return fmt.Errorf("restore not implemented for database type: %s", dbm.config.DatabaseConfig.Type)
	}
}

func (dbm *DatabaseBackupManager) restorePostgreSQLBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	// SECURITY P0 #2: Validate backup path before reading
	if err := validateBackupPath(backupPath, dbm.config.BackupDir); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	// Read and potentially decompress backup
	var backupData []byte
	var err error

	if strings.HasSuffix(backupPath, ".gz") {
		compressed, err := os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("failed to read compressed backup: %w", err)
		}
		backupData, err = gzipDecompress(compressed)
		if err != nil {
			return fmt.Errorf("failed to decompress backup: %w", err)
		}
	} else {
		backupData, err = os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("failed to read backup: %w", err)
		}
	}

	// SECURITY P0 #1: Execute restore with stdin input (no shell injection)
	// SECURITY P1 #5: Set PGPASSWORD via environment (not visible in process list)
	cmd := exec.CommandContext(rc.Ctx, "psql",
		"--host", dbm.config.DatabaseConfig.Host,
		"--port", fmt.Sprintf("%d", dbm.config.DatabaseConfig.Port),
		"--username", dbm.config.DatabaseConfig.Username,
		"--dbname", dbm.config.DatabaseConfig.Database,
		"--no-psqlrc")

	cmd.Env = append(os.Environ(), fmt.Sprintf("PGPASSWORD=%s", dbm.config.DatabaseConfig.Password))
	cmd.Stdin = bytes.NewReader(backupData)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("psql restore failed: %w (stderr: %s)", err, stderr.String())
	}

	return nil
}

func (dbm *DatabaseBackupManager) restoreMySQLBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	// SECURITY P0 #2: Validate backup path before reading
	if err := validateBackupPath(backupPath, dbm.config.BackupDir); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	// Read and potentially decompress backup
	var backupData []byte
	var err error

	if strings.HasSuffix(backupPath, ".gz") {
		compressed, err := os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("failed to read compressed backup: %w", err)
		}
		backupData, err = gzipDecompress(compressed)
		if err != nil {
			return fmt.Errorf("failed to decompress backup: %w", err)
		}
	} else {
		backupData, err = os.ReadFile(backupPath)
		if err != nil {
			return fmt.Errorf("failed to read backup: %w", err)
		}
	}

	// SECURITY P0 #1: Execute restore with stdin input (no shell injection)
	// SECURITY P1 #5: Set MYSQL_PWD via environment (not visible in process list)
	cmd := exec.CommandContext(rc.Ctx, "mysql",
		"--host", dbm.config.DatabaseConfig.Host,
		"--port", fmt.Sprintf("%d", dbm.config.DatabaseConfig.Port),
		"--user", dbm.config.DatabaseConfig.Username,
		dbm.config.DatabaseConfig.Database)

	cmd.Env = append(os.Environ(), fmt.Sprintf("MYSQL_PWD=%s", dbm.config.DatabaseConfig.Password))
	cmd.Stdin = bytes.NewReader(backupData)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("mysql restore failed: %w (stderr: %s)", err, stderr.String())
	}

	return nil
}

func (dbm *DatabaseBackupManager) restoreMongoDBBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	// SECURITY P0 #2: Validate backup path before reading
	if err := validateBackupPath(backupPath, dbm.config.BackupDir); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	var restoreDir string

	if strings.HasSuffix(backupPath, ".tar.gz") {
		// SECURITY P0 #3: Create secure temp directory with proper permissions
		// Don't use hardcoded /tmp path - use os.MkdirTemp for atomic creation
		tempDir, err := os.MkdirTemp("", "mongo_restore_*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory: %w", err)
		}

		// SECURITY P2 #7: Clean up temp directory on exit
		defer func() { _ = os.RemoveAll(tempDir) }()

		// SECURITY P2 #7: Validate backupPath doesn't contain traversal before extraction
		if strings.Contains(backupPath, "..") {
			return fmt.Errorf("backup path contains directory traversal")
		}

		err = execute.RunSimple(rc.Ctx, "tar", "-xzf", backupPath, "-C", tempDir)
		if err != nil {
			return fmt.Errorf("failed to extract backup: %w", err)
		}

		restoreDir = tempDir
	} else {
		restoreDir = backupPath
	}

	args := []string{
		"mongorestore",
		"--host", fmt.Sprintf("%s:%d", dbm.config.DatabaseConfig.Host, dbm.config.DatabaseConfig.Port),
		"--db", dbm.config.DatabaseConfig.Database,
		"--drop", // Drop collections before restoring
		restoreDir,
	}

	if dbm.config.DatabaseConfig.Username != "" {
		args = append(args, "--username", dbm.config.DatabaseConfig.Username)
		args = append(args, "--password", dbm.config.DatabaseConfig.Password)
	}

	return execute.RunSimple(rc.Ctx, args[0], args[1:]...)
}

func (dbm *DatabaseBackupManager) restoreRedisBackup(rc *eos_io.RuntimeContext, backupPath string) error {
	// For Redis, we need to stop the service, replace the RDB file, and restart
	// This is a simplified implementation

	// Stop Redis service
	err := execute.RunSimple(rc.Ctx, "systemctl", "stop", "redis-server")
	if err != nil {
		return fmt.Errorf("failed to stop Redis: %w", err)
	}

	// Copy backup to Redis data directory
	rdbPath := "/var/lib/redis/dump.rdb"
	err = execute.RunSimple(rc.Ctx, "cp", backupPath, rdbPath)
	if err != nil {
		return fmt.Errorf("failed to copy backup: %w", err)
	}

	// Set proper ownership
	err = execute.RunSimple(rc.Ctx, "chown", "redis:redis", rdbPath)
	if err != nil {
		return fmt.Errorf("failed to set ownership: %w", err)
	}

	// Start Redis service
	err = execute.RunSimple(rc.Ctx, "systemctl", "start", "redis-server")
	if err != nil {
		return fmt.Errorf("failed to start Redis: %w", err)
	}

	return nil
}

func (dbm *DatabaseBackupManager) evaluateRestore(rc *eos_io.RuntimeContext) error {
	// Test database connection after restore
	return dbm.testDatabaseConnection(rc)
}

// SECURITY P0 #2: Helper functions for path validation and compression

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// validateBackupPath ensures backupPath is within the allowedDir to prevent path traversal
func validateBackupPath(backupPath, allowedDir string) error {
	// Get absolute paths
	absBackupPath, err := filepath.Abs(backupPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute backup path: %w", err)
	}

	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute allowed directory: %w", err)
	}

	// Clean paths to remove ".." and other relative elements
	cleanBackupPath := filepath.Clean(absBackupPath)
	cleanAllowedDir := filepath.Clean(absAllowedDir)

	// Ensure backup path is within allowed directory
	if !strings.HasPrefix(cleanBackupPath, cleanAllowedDir+string(filepath.Separator)) &&
		cleanBackupPath != cleanAllowedDir {
		return fmt.Errorf("backup path '%s' is outside allowed directory '%s'",
			cleanBackupPath, cleanAllowedDir)
	}

	// Additional checks for common path traversal patterns
	if strings.Contains(backupPath, "..") {
		return fmt.Errorf("backup path contains directory traversal '..'")
	}

	// Check for symlink attacks
	if fileInfo, err := os.Lstat(filepath.Dir(cleanBackupPath)); err == nil {
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup path parent directory is a symlink")
		}
	}

	return nil
}

// gzipCompress compresses data using gzip
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)

	if _, err := gzWriter.Write(data); err != nil {
		return nil, fmt.Errorf("gzip write failed: %w", err)
	}

	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("gzip close failed: %w", err)
	}

	return buf.Bytes(), nil
}

// gzipDecompress decompresses gzip data
func gzipDecompress(data []byte) ([]byte, error) {
	buf := bytes.NewReader(data)
	gzReader, err := gzip.NewReader(buf)
	if err != nil {
		return nil, fmt.Errorf("gzip reader creation failed: %w", err)
	}
	defer func() { _ = gzReader.Close() }()

	var out bytes.Buffer
	if _, err := io.Copy(&out, gzReader); err != nil {
		return nil, fmt.Errorf("gzip decompression failed: %w", err)
	}

	return out.Bytes(), nil
}
