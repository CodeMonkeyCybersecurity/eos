// pkg/database_management/manager.go
package database_management

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DatabaseManager provides database management functionality
type DatabaseManager struct {
	// Configuration and connections can be added here
}

// NewDatabaseManager creates a new DatabaseManager instance
func NewDatabaseManager() *DatabaseManager {
	return &DatabaseManager{}
}

// SetupVaultPostgreSQL sets up Vault dynamic PostgreSQL credentials
func (dm *DatabaseManager) SetupVaultPostgreSQL(rc *eos_io.RuntimeContext, options *VaultSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Setting up Vault dynamic PostgreSQL credentials",
		zap.String("connection_name", options.ConnectionName),
		zap.String("engine_mount", options.EngineMount))

	// Check prerequisites
	if err := dm.checkPrerequisites(rc); err != nil {
		return fmt.Errorf("prerequisites check failed: %w", err)
	}

	// Configure Vault connection if needed
	if err := dm.configureVaultConnection(rc, options); err != nil {
		return fmt.Errorf("vault connection configuration failed: %w", err)
	}

	// Setup database engine
	if err := dm.setupDatabaseEngine(rc, options); err != nil {
		return fmt.Errorf("database engine setup failed: %w", err)
	}

	// Test dynamic credentials
	if options.TestConnection {
		if err := dm.testDynamicCredentials(rc, options); err != nil {
			return fmt.Errorf("dynamic credentials test failed: %w", err)
		}
	}

	logger.Info("Vault PostgreSQL setup completed successfully")
	return nil
}

// GetDatabaseStatus retrieves database status information
func (dm *DatabaseManager) GetDatabaseStatus(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*DatabaseStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting database status", zap.String("database", config.Database))

	switch config.Type {
	case DatabaseTypePostgreSQL:
		return dm.getPostgreSQLStatus(rc, config)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

// ExecuteQuery executes a database query
func (dm *DatabaseManager) ExecuteQuery(rc *eos_io.RuntimeContext, config *DatabaseConfig, operation *DatabaseOperation) (*DatabaseOperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)

	start := time.Now()
	result := &DatabaseOperationResult{
		Timestamp: start,
	}

	logger.Info("Executing database query",
		zap.String("database", config.Database),
		zap.String("type", operation.Type),
		zap.Bool("dry_run", operation.DryRun))

	if operation.DryRun {
		result.Success = true
		result.Message = "Dry run completed - query would be executed"
		result.Duration = time.Since(start)
		return result, nil
	}

	db, err := dm.connect(config)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}
	defer db.Close()

	if operation.Transaction {
		return dm.executeTransaction(db, operation, start)
	}

	return dm.executeSimpleQuery(db, operation, start)
}

// GetSchemaInfo retrieves database schema information
func (dm *DatabaseManager) GetSchemaInfo(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*SchemaInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Getting database schema information", zap.String("database", config.Database))

	switch config.Type {
	case DatabaseTypePostgreSQL:
		return dm.getPostgreSQLSchemaInfo(rc, config)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

// GenerateCredentials generates dynamic database credentials using Vault
func (dm *DatabaseManager) GenerateCredentials(rc *eos_io.RuntimeContext, options *VaultOperationOptions) (*DatabaseCredential, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Generating dynamic database credentials",
		zap.String("role", options.RoleName),
		zap.String("engine_mount", options.EngineMount))

	if options.DryRun {
		logger.Info("Dry run - would generate credentials for role", zap.String("role", options.RoleName))
		return &DatabaseCredential{
			Username: "dry_run_user",
			Password: "dry_run_password",
			LeaseID:  "dry_run_lease",
		}, nil
	}

	return dm.generateVaultCredentials(rc, options)
}

// RevokeCredentials revokes dynamic database credentials
func (dm *DatabaseManager) RevokeCredentials(rc *eos_io.RuntimeContext, leaseID string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Revoking database credentials", zap.String("lease_id", leaseID))

	cmd := exec.Command("vault", "lease", "revoke", leaseID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Failed to revoke credentials", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("failed to revoke credentials: %w", err)
	}

	logger.Info("Credentials revoked successfully")
	return nil
}

// PerformHealthCheck performs a comprehensive database health check
func (dm *DatabaseManager) PerformHealthCheck(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*DatabaseHealthCheck, error) {
	logger := otelzap.Ctx(rc.Ctx)

	start := time.Now()
	healthCheck := &DatabaseHealthCheck{
		Database:  config.Database,
		Timestamp: start,
		Checks:    make([]HealthCheckItem, 0),
	}

	logger.Info("Performing database health check", zap.String("database", config.Database))

	// Connection test
	db, err := dm.connect(config)
	if err != nil {
		healthCheck.Healthy = false
		healthCheck.Error = err.Error()
		healthCheck.ResponseTime = time.Since(start)
		healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
			Name:    "Connection Test",
			Status:  "FAILED",
			Message: err.Error(),
		})
		return healthCheck, err
	}
	defer db.Close()

	healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
		Name:   "Connection Test",
		Status: "PASSED",
	})

	// Ping test
	if err := db.Ping(); err != nil {
		healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
			Name:    "Ping Test",
			Status:  "FAILED",
			Message: err.Error(),
		})
	} else {
		healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
			Name:   "Ping Test",
			Status: "PASSED",
		})
	}

	// Simple query test
	var result int
	err = db.QueryRow("SELECT 1").Scan(&result)
	if err != nil {
		healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
			Name:    "Query Test",
			Status:  "FAILED",
			Message: err.Error(),
		})
	} else {
		healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
			Name:   "Query Test",
			Status: "PASSED",
		})
	}

	// Determine overall health
	healthCheck.Healthy = true
	for _, check := range healthCheck.Checks {
		if check.Status == "FAILED" {
			healthCheck.Healthy = false
			break
		}
	}

	healthCheck.ResponseTime = time.Since(start)
	logger.Info("Health check completed",
		zap.Bool("healthy", healthCheck.Healthy),
		zap.Duration("response_time", healthCheck.ResponseTime))

	return healthCheck, nil
}

// Helper methods

func (dm *DatabaseManager) checkPrerequisites(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if vault command exists
	if _, err := exec.LookPath("vault"); err != nil {
		return fmt.Errorf("vault CLI not found: %w", err)
	}

	// Check if psql command exists for PostgreSQL operations
	if _, err := exec.LookPath("psql"); err != nil {
		logger.Warn("psql command not found - some PostgreSQL operations may not work")
	}

	logger.Info("Prerequisites check passed")
	return nil
}

func (dm *DatabaseManager) configureVaultConnection(rc *eos_io.RuntimeContext, options *VaultSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if VAULT_ADDR is set
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		if options.Interactive {
			logger.Info("VAULT_ADDR not set. Please configure Vault connection first")
			return fmt.Errorf("vault configuration required")
		}
		return fmt.Errorf("VAULT_ADDR environment variable not set")
	}

	logger.Info("Vault connection configured", zap.String("vault_addr", vaultAddr))
	return nil
}

func (dm *DatabaseManager) setupDatabaseEngine(rc *eos_io.RuntimeContext, options *VaultSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Enable database secrets engine
	logger.Info("Enabling database secrets engine")
	cmd := exec.Command("vault", "secrets", "list")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list secrets engines: %w", err)
	}

	engineMount := options.EngineMount
	if engineMount == "" {
		engineMount = "database/"
	}

	if !strings.Contains(string(output), engineMount) {
		cmd = exec.Command("vault", "secrets", "enable", "database")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to enable database secrets engine: %w", err)
		}
		logger.Info("Database secrets engine enabled")
	} else {
		logger.Info("Database secrets engine already enabled")
	}

	// Configure PostgreSQL connection
	connectionName := options.ConnectionName
	if connectionName == "" {
		connectionName = "delphi-postgresql"
	}

	config := options.DatabaseConfig
	connectionURL := fmt.Sprintf("postgresql://{{username}}:{{password}}@%s:%d/%s?sslmode=%s",
		config.Host, config.Port, config.Database, config.SSLMode)

	cmd = exec.Command("vault", "write", fmt.Sprintf("database/config/%s", connectionName),
		"plugin_name=postgresql-database-plugin",
		fmt.Sprintf("connection_url=%s", connectionURL),
		"allowed_roles=delphi-readonly",
		fmt.Sprintf("username=%s", options.AdminUsername),
		fmt.Sprintf("password=%s", options.AdminPassword))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure PostgreSQL connection: %w", err)
	}

	logger.Info("PostgreSQL connection configured")

	// Create roles
	for _, role := range options.Roles {
		if err := dm.createVaultRole(rc, connectionName, role); err != nil {
			return fmt.Errorf("failed to create role %s: %w", role.Name, err)
		}
	}

	return nil
}

func (dm *DatabaseManager) createVaultRole(rc *eos_io.RuntimeContext, connectionName string, role *Role) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Creating Vault database role", zap.String("role", role.Name))

	creationStatements := strings.Join(role.CreationStatements, "; ")

	args := []string{
		"write", fmt.Sprintf("database/roles/%s", role.Name),
		fmt.Sprintf("db_name=%s", connectionName),
		fmt.Sprintf("creation_statements=%s", creationStatements),
		fmt.Sprintf("default_ttl=%s", role.DefaultTTL.String()),
		fmt.Sprintf("max_ttl=%s", role.MaxTTL.String()),
	}

	if len(role.RevocationStatements) > 0 {
		revocationStatements := strings.Join(role.RevocationStatements, "; ")
		args = append(args, fmt.Sprintf("revocation_statements=%s", revocationStatements))
	}

	cmd := exec.Command("vault", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	logger.Info("Vault database role created successfully", zap.String("role", role.Name))
	return nil
}

func (dm *DatabaseManager) testDynamicCredentials(rc *eos_io.RuntimeContext, options *VaultSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Testing dynamic credential generation")

	for _, role := range options.Roles {
		cmd := exec.Command("vault", "read", "-format=json", fmt.Sprintf("database/creds/%s", role.Name))
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to generate credentials for role %s: %w", role.Name, err)
		}

		var credResp map[string]interface{}
		if err := json.Unmarshal(output, &credResp); err != nil {
			return fmt.Errorf("failed to parse credential response: %w", err)
		}

		logger.Info("Dynamic credentials generated successfully",
			zap.String("role", role.Name),
			zap.Any("lease_duration", credResp["lease_duration"]))
	}

	return nil
}

func (dm *DatabaseManager) generateVaultCredentials(rc *eos_io.RuntimeContext, options *VaultOperationOptions) (*DatabaseCredential, error) {
	cmd := exec.Command("vault", "read", "-format=json",
		fmt.Sprintf("%s/creds/%s", strings.TrimSuffix(options.EngineMount, "/"), options.RoleName))

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to generate credentials: %w", err)
	}

	var credResp map[string]interface{}
	if err := json.Unmarshal(output, &credResp); err != nil {
		return nil, fmt.Errorf("failed to parse credential response: %w", err)
	}

	data, ok := credResp["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid credential response format")
	}

	leaseDuration, _ := credResp["lease_duration"].(float64)
	renewable, _ := credResp["renewable"].(bool)
	leaseID, _ := credResp["lease_id"].(string)

	credential := &DatabaseCredential{
		Username:      data["username"].(string),
		Password:      data["password"].(string),
		LeaseID:       leaseID,
		LeaseDuration: int(leaseDuration),
		Renewable:     renewable,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(time.Duration(leaseDuration) * time.Second),
	}

	return credential, nil
}

func (dm *DatabaseManager) connect(config *DatabaseConfig) (*sql.DB, error) {
	switch config.Type {
	case DatabaseTypePostgreSQL:
		return dm.connectPostgreSQL(config)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

func (dm *DatabaseManager) connectPostgreSQL(config *DatabaseConfig) (*sql.DB, error) {
	sslMode := config.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.Username, config.Password, config.Database, sslMode)

	if config.Timeout > 0 {
		dsn += fmt.Sprintf(" connect_timeout=%d", config.Timeout)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	if config.MaxConns > 0 {
		db.SetMaxOpenConns(config.MaxConns)
	}

	return db, nil
}

func (dm *DatabaseManager) getPostgreSQLStatus(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*DatabaseStatus, error) {
	db, err := dm.connectPostgreSQL(config)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	status := &DatabaseStatus{
		Type: DatabaseTypePostgreSQL,
	}

	// Get version
	var version string
	err = db.QueryRow("SELECT version()").Scan(&version)
	if err == nil {
		status.Version = version
	}

	// Get connection count
	var connections int
	err = db.QueryRow("SELECT count(*) FROM pg_stat_activity").Scan(&connections)
	if err == nil {
		status.Connections = connections
	}

	// Get max connections
	var maxConnections int
	err = db.QueryRow("SHOW max_connections").Scan(&maxConnections)
	if err == nil {
		status.MaxConnections = maxConnections
	}

	// Get database size
	var dbSize string
	err = db.QueryRow("SELECT pg_size_pretty(pg_database_size($1))", config.Database).Scan(&dbSize)
	if err == nil {
		status.DatabaseSize = dbSize
	}

	status.Status = "running"
	return status, nil
}

func (dm *DatabaseManager) getPostgreSQLSchemaInfo(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*SchemaInfo, error) {
	db, err := dm.connectPostgreSQL(config)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	schemaInfo := &SchemaInfo{
		Database: config.Database,
		Tables:   make([]TableInfo, 0),
	}

	// Get tables
	query := `
		SELECT table_name, table_schema 
		FROM information_schema.tables 
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var tableName, tableSchema string
		if err := rows.Scan(&tableName, &tableSchema); err != nil {
			continue
		}

		tableInfo := TableInfo{
			Name:   tableName,
			Schema: tableSchema,
		}

		// Get columns for this table
		columns, err := dm.getTableColumns(db, tableName, tableSchema)
		if err == nil {
			tableInfo.Columns = columns
		}

		schemaInfo.Tables = append(schemaInfo.Tables, tableInfo)
	}

	return schemaInfo, nil
}

func (dm *DatabaseManager) getTableColumns(db *sql.DB, tableName, tableSchema string) ([]ColumnInfo, error) {
	query := `
		SELECT column_name, data_type, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_name = $1 AND table_schema = $2
		ORDER BY ordinal_position
	`

	rows, err := db.Query(query, tableName, tableSchema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []ColumnInfo
	for rows.Next() {
		var columnName, dataType, isNullable string
		var columnDefault sql.NullString

		if err := rows.Scan(&columnName, &dataType, &isNullable, &columnDefault); err != nil {
			continue
		}

		column := ColumnInfo{
			Name:     columnName,
			Type:     dataType,
			Nullable: isNullable == "YES",
		}

		if columnDefault.Valid {
			column.DefaultValue = columnDefault.String
		}

		columns = append(columns, column)
	}

	return columns, nil
}

func (dm *DatabaseManager) executeSimpleQuery(db *sql.DB, operation *DatabaseOperation, start time.Time) (*DatabaseOperationResult, error) {
	result := &DatabaseOperationResult{
		Timestamp: start,
	}

	rows, err := db.Query(operation.Query)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	var data []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			continue
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		data = append(data, row)
	}

	result.Success = true
	result.Data = data
	result.Message = fmt.Sprintf("Query executed successfully, %d rows returned", len(data))
	result.Duration = time.Since(start)

	return result, nil
}

func (dm *DatabaseManager) executeTransaction(db *sql.DB, operation *DatabaseOperation, start time.Time) (*DatabaseOperationResult, error) {
	result := &DatabaseOperationResult{
		Timestamp: start,
	}

	tx, err := db.Begin()
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	res, err := tx.Exec(operation.Query)
	if err != nil {
		tx.Rollback()
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	if err := tx.Commit(); err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	rowsAffected, _ := res.RowsAffected()
	result.Success = true
	result.RowsAffected = rowsAffected
	result.Message = fmt.Sprintf("Transaction completed successfully, %d rows affected", rowsAffected)
	result.Duration = time.Since(start)

	return result, nil
}
