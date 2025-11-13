// pkg/database_management/types.go
package database_management

import (
	"time"
)

// DatabaseType represents the type of database
type DatabaseType string

const (
	DatabaseTypePostgreSQL DatabaseType = "postgresql"
	DatabaseTypeMySQL      DatabaseType = "mysql"
	DatabaseTypeSQLite     DatabaseType = "sqlite"
	DatabaseTypeMongoDB    DatabaseType = "mongodb"
	DatabaseTypeRedis      DatabaseType = "redis"
)

// DatabaseConfig represents database connection configuration
type DatabaseConfig struct {
	Type     DatabaseType `json:"type"`
	Host     string       `json:"host"`
	Port     int          `json:"port"`
	Database string       `json:"database"`
	Username string       `json:"username"`
	Password string       `json:"password,omitempty"`
	SSLMode  string       `json:"ssl_mode,omitempty"`
	Timeout  int          `json:"timeout,omitempty"`
	MaxConns int          `json:"max_connections,omitempty"`
}

// VaultDatabaseConfig represents Vault dynamic database configuration
type VaultDatabaseConfig struct {
	VaultAddr      string           `json:"vault_addr"`
	VaultToken     string           `json:"vault_token,omitempty"`
	DatabaseConfig *DatabaseConfig  `json:"database_config"`
	AdminUsername  string           `json:"admin_username"`
	AdminPassword  string           `json:"admin_password,omitempty"`
	Roles          map[string]*Role `json:"roles"`
	EngineMount    string           `json:"engine_mount"`
	ConnectionName string           `json:"connection_name"`
}

// Role represents a Vault database role configuration
type Role struct {
	Name                 string        `json:"name"`
	DBName               string        `json:"db_name"`
	CreationStatements   []string      `json:"creation_statements"`
	RevocationStatements []string      `json:"revocation_statements,omitempty"`
	RollbackStatements   []string      `json:"rollback_statements,omitempty"`
	RenewStatements      []string      `json:"renew_statements,omitempty"`
	DefaultTTL           time.Duration `json:"default_ttl"`
	MaxTTL               time.Duration `json:"max_ttl"`
}

// DatabaseCredential represents dynamic database credentials
type DatabaseCredential struct {
	Username      string    `json:"username"`
	Password      string    `json:"password"`
	LeaseID       string    `json:"lease_id"`
	LeaseDuration int       `json:"lease_duration"`
	Renewable     bool      `json:"renewable"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// DatabaseOperation represents a database operation
type DatabaseOperation struct {
	Type        string                 `json:"type"`
	Database    string                 `json:"database"`
	Query       string                 `json:"query,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Transaction bool                   `json:"transaction"`
	DryRun      bool                   `json:"dry_run"`
}

// SchemaInfo represents database schema information
type SchemaInfo struct {
	Database string        `json:"database"`
	Tables   []TableInfo   `json:"tables"`
	Views    []ViewInfo    `json:"views,omitempty"`
	Indexes  []IndexInfo   `json:"indexes,omitempty"`
	Triggers []TriggerInfo `json:"triggers,omitempty"`
}

// TableInfo represents database table information
type TableInfo struct {
	Name     string       `json:"name"`
	Schema   string       `json:"schema"`
	Columns  []ColumnInfo `json:"columns"`
	RowCount int64        `json:"row_count,omitempty"`
	Size     string       `json:"size,omitempty"`
}

// ColumnInfo represents database column information
type ColumnInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Nullable     bool   `json:"nullable"`
	DefaultValue string `json:"default_value,omitempty"`
	IsPrimaryKey bool   `json:"is_primary_key"`
	IsForeignKey bool   `json:"is_foreign_key"`
}

// ViewInfo represents database view information
type ViewInfo struct {
	Name       string `json:"name"`
	Schema     string `json:"schema"`
	Definition string `json:"definition"`
}

// IndexInfo represents database index information
type IndexInfo struct {
	Name    string   `json:"name"`
	Table   string   `json:"table"`
	Columns []string `json:"columns"`
	Unique  bool     `json:"unique"`
	Type    string   `json:"type"`
}

// TriggerInfo represents database trigger information
type TriggerInfo struct {
	Name       string `json:"name"`
	Table      string `json:"table"`
	Event      string `json:"event"`
	Timing     string `json:"timing"`
	Definition string `json:"definition"`
}

// MigrationInfo represents database migration information
type MigrationInfo struct {
	Version     string    `json:"version"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	FilePath    string    `json:"file_path"`
	Applied     bool      `json:"applied"`
	AppliedAt   time.Time `json:"applied_at,omitempty"`
	Checksum    string    `json:"checksum"`
}

// BackupInfo represents database backup information
type BackupInfo struct {
	Database   string    `json:"database"`
	FilePath   string    `json:"file_path"`
	Size       int64     `json:"size"`
	Compressed bool      `json:"compressed"`
	CreatedAt  time.Time `json:"created_at"`
	Type       string    `json:"type"` // full, incremental, differential
	Checksum   string    `json:"checksum"`
}

// DatabaseStatus represents database status information
type DatabaseStatus struct {
	Type           DatabaseType  `json:"type"`
	Version        string        `json:"version"`
	Status         string        `json:"status"`
	Uptime         time.Duration `json:"uptime"`
	Connections    int           `json:"connections"`
	MaxConnections int           `json:"max_connections"`
	DatabaseSize   string        `json:"database_size"`
	Memory         string        `json:"memory_usage,omitempty"`
	CPU            float64       `json:"cpu_usage,omitempty"`
}

// VaultOperationOptions represents options for Vault database operations
type VaultOperationOptions struct {
	EngineMount    string        `json:"engine_mount"`
	ConnectionName string        `json:"connection_name"`
	RoleName       string        `json:"role_name"`
	Force          bool          `json:"force"`
	DryRun         bool          `json:"dry_run"`
	TTL            time.Duration `json:"ttl,omitempty"`
	Interactive    bool          `json:"interactive"`
}

// DatabaseOperationResult represents the result of a database operation
type DatabaseOperationResult struct {
	Success      bool                     `json:"success"`
	Message      string                   `json:"message"`
	RowsAffected int64                    `json:"rows_affected,omitempty"`
	Data         []map[string]interface{} `json:"data,omitempty"`
	Error        string                   `json:"error,omitempty"`
	Duration     time.Duration            `json:"duration"`
	Timestamp    time.Time                `json:"timestamp"`
}

// VaultSetupOptions represents options for setting up Vault database integration
type VaultSetupOptions struct {
	DatabaseConfig *DatabaseConfig `json:"database_config"`
	AdminUsername  string          `json:"admin_username"`
	AdminPassword  string          `json:"admin_password"`
	ConnectionName string          `json:"connection_name"`
	EngineMount    string          `json:"engine_mount"`
	Roles          []*Role         `json:"roles"`
	TestConnection bool            `json:"test_connection"`
	Interactive    bool            `json:"interactive"`
	Force          bool            `json:"force"`
}

// PostgreSQLSpecificConfig represents PostgreSQL-specific configuration
type PostgreSQLSpecificConfig struct {
	SearchPath        string `json:"search_path,omitempty"`
	ApplicationName   string `json:"application_name,omitempty"`
	ConnectTimeout    int    `json:"connect_timeout,omitempty"`
	StatementTimeout  int    `json:"statement_timeout,omitempty"`
	IdleInTransaction int    `json:"idle_in_transaction,omitempty"`
}

// DatabaseHealthCheck represents a database health check result
type DatabaseHealthCheck struct {
	Database     string            `json:"database"`
	Healthy      bool              `json:"healthy"`
	ResponseTime time.Duration     `json:"response_time"`
	Error        string            `json:"error,omitempty"`
	Checks       []HealthCheckItem `json:"checks"`
	Timestamp    time.Time         `json:"timestamp"`
}

// HealthCheckItem represents an individual health check item
type HealthCheckItem struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}
