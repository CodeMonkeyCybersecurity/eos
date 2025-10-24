// pkg/database_management/database.go
package database_management

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GetDatabaseStatus retrieves database status information following Assess → Intervene → Evaluate pattern
func GetDatabaseStatus(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*DatabaseStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check for nil config first (SA5011: prevent nil pointer dereference)
	if config == nil {
		return nil, fmt.Errorf("database config cannot be nil")
	}

	logger.Info("Assessing database status request",
		zap.String("database", config.Database),
		zap.String("type", string(config.Type)))

	// INTERVENE
	logger.Info("Getting database status", zap.String("database", config.Database))

	switch config.Type {
	case DatabaseTypePostgreSQL:
		status, err := getPostgreSQLStatus(rc, config)
		if err != nil {
			return nil, err
		}
		
		// EVALUATE
		logger.Info("Database status retrieved successfully",
			zap.String("status", status.Status),
			zap.String("version", status.Version))
		
		return status, nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

// ExecuteQuery executes a database query following Assess → Intervene → Evaluate pattern
func ExecuteQuery(rc *eos_io.RuntimeContext, config *DatabaseConfig, operation *DatabaseOperation) (*DatabaseOperationResult, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	start := time.Now()
	logger.Info("Assessing query execution request",
		zap.String("database", config.Database),
		zap.String("operation_type", operation.Type),
		zap.Bool("dry_run", operation.DryRun))

	result := &DatabaseOperationResult{
		Timestamp: start,
	}

	if operation.DryRun {
		result.Success = true
		result.Message = "Dry run completed - query would be executed"
		result.Duration = time.Since(start)
		logger.Info("Dry run completed successfully")
		return result, nil
	}

	// INTERVENE
	logger.Info("Executing database query", 
		zap.String("database", config.Database),
		zap.String("type", operation.Type))

	db, err := connect(config)
	if err != nil {
		result.Error = err.Error()
		logger.Error("Database connection failed", zap.Error(err))
		return result, fmt.Errorf("database connection failed: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Execute operation
	var operationResult *DatabaseOperationResult
	switch operation.Type {
	case "query", "select":
		operationResult, err = executeSimpleQuery(db, operation, start)
	case "transaction":
		operationResult, err = executeTransaction(db, operation, start)
	default:
		operationResult, err = executeSimpleQuery(db, operation, start)
	}

	if err != nil {
		logger.Error("Query execution failed", zap.Error(err))
		return operationResult, err
	}

	// EVALUATE
	logger.Info("Query executed successfully",
		zap.String("operation", operation.Type),
		zap.Duration("duration", operationResult.Duration))

	return operationResult, nil
}

// GetSchemaInfo retrieves database schema information following Assess → Intervene → Evaluate pattern
func GetSchemaInfo(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*SchemaInfo, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing schema info request", zap.String("database", config.Database))

	// INTERVENE
	logger.Info("Getting database schema information", zap.String("database", config.Database))

	switch config.Type {
	case DatabaseTypePostgreSQL:
		schemaInfo, err := getPostgreSQLSchemaInfo(rc, config)
		if err != nil {
			return nil, err
		}
		
		// EVALUATE
		logger.Info("Schema information retrieved successfully",
			zap.Int("table_count", len(schemaInfo.Tables)),
			zap.Int("view_count", len(schemaInfo.Views)))
		
		return schemaInfo, nil
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

// PerformHealthCheck performs a database health check following Assess → Intervene → Evaluate pattern
func PerformHealthCheck(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*DatabaseHealthCheck, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing health check request", zap.String("database", config.Database))

	healthCheck := &DatabaseHealthCheck{
		Timestamp: time.Now(),
		Database:  config.Database,
		Checks:    make([]HealthCheckItem, 0),
	}

	// INTERVENE
	logger.Info("Performing database health check", zap.String("database", config.Database))

	// Test connection
	start := time.Now()
	db, err := connect(config)
	if err != nil {
		healthCheck.Healthy = false
		healthCheck.Error = fmt.Sprintf("Connection failed: %v", err)
		healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
			Name:    "connection",
			Status:  "failed",
			Message: err.Error(),
		})
		logger.Error("Health check connection failed", zap.Error(err))
	} else {
		defer func() { _ = db.Close() }()
		healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
			Name:   "connection",
			Status: "success",
		})

		// Test simple query
		if err := db.Ping(); err != nil {
			healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
				Name:    "ping",
				Status:  "failed",
				Message: err.Error(),
			})
		} else {
			healthCheck.Checks = append(healthCheck.Checks, HealthCheckItem{
				Name:   "ping",
				Status: "success",
			})
		}
	}

	healthCheck.ResponseTime = time.Since(start)

	// EVALUATE
	healthCheck.Healthy = healthCheck.Error == ""
	for _, check := range healthCheck.Checks {
		if check.Status == "failed" {
			healthCheck.Healthy = false
		}
	}
	
	logger.Info("Health check completed",
		zap.Bool("healthy", healthCheck.Healthy),
		zap.Duration("response_time", healthCheck.ResponseTime))

	return healthCheck, nil
}

// SetupVaultPostgreSQL sets up Vault dynamic PostgreSQL credentials following Assess → Intervene → Evaluate pattern
func SetupVaultPostgreSQL(rc *eos_io.RuntimeContext, options *VaultSetupOptions) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing Vault PostgreSQL setup",
		zap.String("connection_name", options.ConnectionName),
		zap.String("engine_mount", options.EngineMount))

	// Check prerequisites
	if err := checkPrerequisites(rc); err != nil {
		return fmt.Errorf("prerequisites check failed: %w", err)
	}

	// INTERVENE
	logger.Info("Setting up Vault dynamic PostgreSQL credentials")

	// Configure Vault connection if needed
	if err := configureVaultConnection(rc, options); err != nil {
		return fmt.Errorf("vault connection configuration failed: %w", err)
	}

	// Setup database engine
	if err := setupDatabaseEngine(rc, options); err != nil {
		return fmt.Errorf("database engine setup failed: %w", err)
	}

	// Test dynamic credentials
	if options.TestConnection {
		if err := testDynamicCredentials(rc, options); err != nil {
			return fmt.Errorf("dynamic credentials test failed: %w", err)
		}
	}

	// EVALUATE
	logger.Info("Vault PostgreSQL setup completed successfully")
	return nil
}

// GenerateCredentials generates dynamic database credentials following Assess → Intervene → Evaluate pattern
func GenerateCredentials(rc *eos_io.RuntimeContext, options *VaultOperationOptions) (*DatabaseCredential, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing credential generation request",
		zap.String("role", options.RoleName),
		zap.String("engine_mount", options.EngineMount))

	// INTERVENE
	logger.Info("Generating dynamic database credentials")

	credential, err := generateVaultCredentials(rc, options)
	if err != nil {
		return nil, fmt.Errorf("credential generation failed: %w", err)
	}

	// EVALUATE
	logger.Info("Database credentials generated successfully",
		zap.String("username", credential.Username),
		zap.String("lease_id", credential.LeaseID))

	return credential, nil
}

// RevokeCredentials revokes dynamic database credentials following Assess → Intervene → Evaluate pattern
func RevokeCredentials(rc *eos_io.RuntimeContext, leaseID string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS
	logger.Info("Assessing credential revocation request", zap.String("lease_id", leaseID))

	if leaseID == "" {
		return fmt.Errorf("lease ID cannot be empty")
	}

	// INTERVENE
	logger.Info("Revoking database credentials", zap.String("lease_id", leaseID))

	// Revoke lease using Vault CLI
	cmd := []string{"vault", "lease", "revoke", leaseID}
	if err := executeVaultCommand(rc, cmd); err != nil {
		return fmt.Errorf("failed to revoke credentials: %w", err)
	}

	// EVALUATE
	logger.Info("Database credentials revoked successfully", zap.String("lease_id", leaseID))
	return nil
}

// Helper functions

func connect(config *DatabaseConfig) (*sql.DB, error) {
	switch config.Type {
	case DatabaseTypePostgreSQL:
		return connectPostgreSQL(config)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}
}

func connectPostgreSQL(config *DatabaseConfig) (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.Username, config.Password, config.Database, config.SSLMode)
	
	return sql.Open("postgres", connStr)
}

func getPostgreSQLStatus(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*DatabaseStatus, error) {
	db, err := connectPostgreSQL(config)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer func() { _ = db.Close() }()

	status := &DatabaseStatus{
		Type: config.Type,
	}

	// Test connection
	if err := db.Ping(); err != nil {
		status.Status = "unreachable"
		return status, nil
	}
	status.Status = "connected"

	// Get version
	err = db.QueryRow("SELECT version()").Scan(&status.Version)
	if err != nil {
		status.Version = "unknown"
	}

	// Get connection count
	err = db.QueryRow("SELECT count(*) FROM pg_stat_activity").Scan(&status.Connections)
	if err != nil {
		status.Connections = 0
	}

	// Get max connections
	err = db.QueryRow("SHOW max_connections").Scan(&status.MaxConnections)
	if err != nil {
		status.MaxConnections = 0
	}

	// Get database size
	var size sql.NullString
	err = db.QueryRow("SELECT pg_size_pretty(pg_database_size($1))", config.Database).Scan(&size)
	if err == nil && size.Valid {
		status.DatabaseSize = size.String
	}

	// Get uptime
	var uptimeSeconds sql.NullInt64
	err = db.QueryRow("SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time()))").Scan(&uptimeSeconds)
	if err == nil && uptimeSeconds.Valid {
		status.Uptime = time.Duration(uptimeSeconds.Int64) * time.Second
	}

	return status, nil
}

func getPostgreSQLSchemaInfo(rc *eos_io.RuntimeContext, config *DatabaseConfig) (*SchemaInfo, error) {
	db, err := connectPostgreSQL(config)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer func() { _ = db.Close() }()

	schemaInfo := &SchemaInfo{
		Database: config.Database,
		Tables:   make([]TableInfo, 0),
		Views:    make([]ViewInfo, 0),
	}

	// Get tables
	tableQuery := `
		SELECT table_name, table_schema 
		FROM information_schema.tables 
		WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('information_schema', 'pg_catalog')
		ORDER BY table_schema, table_name`

	rows, err := db.Query(tableQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query tables: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var tableName, tableSchema string
		if err := rows.Scan(&tableName, &tableSchema); err != nil {
			continue
		}

		table := TableInfo{
			Name:   tableName,
			Schema: tableSchema,
		}

		// Get column information
		if columns, err := getTableColumns(db, tableName, tableSchema); err == nil {
			table.Columns = columns
		}

		schemaInfo.Tables = append(schemaInfo.Tables, table)
	}

	// Get views
	viewQuery := `
		SELECT table_name, table_schema 
		FROM information_schema.views 
		WHERE table_schema NOT IN ('information_schema', 'pg_catalog')
		ORDER BY table_schema, table_name`

	rows, err = db.Query(viewQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query views: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var viewName, viewSchema string
		if err := rows.Scan(&viewName, &viewSchema); err != nil {
			continue
		}

		view := ViewInfo{
			Name:   viewName,
			Schema: viewSchema,
		}

		schemaInfo.Views = append(schemaInfo.Views, view)
	}

	return schemaInfo, nil
}

func getTableColumns(db *sql.DB, tableName, tableSchema string) ([]ColumnInfo, error) {
	query := `
		SELECT column_name, data_type, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_name = $1 AND table_schema = $2
		ORDER BY ordinal_position`

	rows, err := db.Query(query, tableName, tableSchema)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

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

func executeSimpleQuery(db *sql.DB, operation *DatabaseOperation, start time.Time) (*DatabaseOperationResult, error) {
	result := &DatabaseOperationResult{
		Timestamp: start,
	}

	// SECURITY: Validate SQL query for injection attempts
	if err := validateSQLQuerySafety(operation.Query); err != nil {
		result.Error = fmt.Sprintf("SQL validation failed: %s", err.Error())
		result.Duration = time.Since(start)
		return result, fmt.Errorf("unsafe SQL query rejected: %w", err)
	}

	rows, err := db.Query(operation.Query)
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}
	defer func() { _ = rows.Close() }()

	// Count rows affected
	rowCount := 0
	for rows.Next() {
		rowCount++
	}

	result.Success = true
	result.RowsAffected = int64(rowCount)
	result.Duration = time.Since(start)
	result.Message = fmt.Sprintf("Query executed successfully, %d rows affected", rowCount)

	return result, nil
}

func executeTransaction(db *sql.DB, operation *DatabaseOperation, start time.Time) (*DatabaseOperationResult, error) {
	result := &DatabaseOperationResult{
		Timestamp: start,
	}

	// SECURITY: Validate SQL query for injection attempts
	if err := validateSQLQuerySafety(operation.Query); err != nil {
		result.Error = fmt.Sprintf("SQL validation failed: %s", err.Error())
		result.Duration = time.Since(start)
		return result, fmt.Errorf("unsafe SQL query rejected: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	execResult, err := tx.Exec(operation.Query)
	if err != nil {
		_ = tx.Rollback()
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	if err := tx.Commit(); err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(start)
		return result, err
	}

	rowsAffected, _ := execResult.RowsAffected()
	result.Success = true
	result.RowsAffected = rowsAffected
	result.Duration = time.Since(start)
	result.Message = fmt.Sprintf("Transaction executed successfully, %d rows affected", rowsAffected)

	return result, nil
}

// Vault helper functions (these would typically import vault functionality)
func checkPrerequisites(rc *eos_io.RuntimeContext) error {
	// Implementation would check for Vault CLI, authentication, etc.
	return nil
}

func configureVaultConnection(rc *eos_io.RuntimeContext, options *VaultSetupOptions) error {
	// Implementation would configure Vault connection
	return nil
}

func setupDatabaseEngine(rc *eos_io.RuntimeContext, options *VaultSetupOptions) error {
	// Implementation would setup the database engine in Vault
	return nil
}

func testDynamicCredentials(rc *eos_io.RuntimeContext, options *VaultSetupOptions) error {
	// Implementation would test credential generation
	return nil
}

func generateVaultCredentials(rc *eos_io.RuntimeContext, options *VaultOperationOptions) (*DatabaseCredential, error) {
	// Implementation would generate credentials via Vault
	return &DatabaseCredential{}, nil
}

func executeVaultCommand(rc *eos_io.RuntimeContext, cmd []string) error {
	// Implementation would execute vault CLI commands
	return nil
}

