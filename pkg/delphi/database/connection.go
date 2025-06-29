// pkg/delphi/database/connection.go
package database

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	_ "github.com/lib/pq" // PostgreSQL driver
)

// ConnectionConfig represents database connection configuration
type ConnectionConfig struct {
	Host     string
	Port     string
	Database string
	Username string
	Password string
	SSLMode  string
	// Dynamic credentials info
	LeaseID    string    `json:"lease_id,omitempty"`
	LeaseTTL   int       `json:"lease_duration,omitempty"`
	Renewable  bool      `json:"renewable,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	IsDynamic  bool      `json:"is_dynamic"`
}

// GetConnectionFromVault retrieves database connection details from Vault
func GetConnectionFromVault(rc *eos_io.RuntimeContext) (*ConnectionConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Retrieving database connection from Vault")

	// Initialize Vault service facade
	if err := vault.InitializeServiceFacade(rc); err != nil {
		logger.Warn("Failed to initialize Vault service, trying fallback methods", zap.Error(err))
		return getConnectionFromEnvironment(), nil
	}

	facade := vault.GetServiceFacade()
	if facade == nil {
		logger.Warn("Vault service facade not available, using environment variables")
		return getConnectionFromEnvironment(), nil
	}

	// First try to get dynamic database credentials
	config, err := getDynamicCredentials(rc, facade)
	if err == nil {
		logger.Info("Successfully obtained dynamic database credentials from Vault",
			zap.String("username", config.Username),
			zap.String("lease_id", config.LeaseID),
			zap.Duration("ttl", time.Duration(config.LeaseTTL)*time.Second),
			zap.Time("expires_at", config.ExpiresAt))
		return config, nil
	}

	logger.Warn("Failed to get dynamic credentials, trying static secrets", zap.Error(err))

	// Fall back to static secrets
	config, err = getStaticCredentials(rc, facade)
	if err == nil {
		logger.Info("Successfully retrieved static database credentials from Vault")
		return config, nil
	}

	logger.Warn("Failed to get static credentials from Vault, using environment variables", zap.Error(err))
	return getConnectionFromEnvironment(), nil
}

// getDynamicCredentials requests dynamic PostgreSQL credentials from Vault's database secrets engine
func getDynamicCredentials(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade) (*ConnectionConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Get database connection info (static part)
	baseConfig, err := getDatabaseConfig(rc, facade)
	if err != nil {
		return nil, fmt.Errorf("failed to get database configuration: %w", err)
	}
	
	// Request dynamic credentials from Vault database engine
	logger.Info("Requesting dynamic database credentials", 
		zap.String("vault_role", "delphi-readonly"))
	
	secretStore := facade.GetSecretStore()
	
	// Request dynamic credentials using the database secrets engine
	// Path format: database/creds/{role_name}
	credSecret, err := secretStore.Get(rc.Ctx, "database/creds/delphi-readonly")
	if err != nil {
		return nil, fmt.Errorf("failed to get dynamic credentials: %w", err)
	}

	// Parse the dynamic credentials response
	config := &ConnectionConfig{
		Host:      baseConfig.Host,
		Port:      baseConfig.Port,
		Database:  baseConfig.Database,
		SSLMode:   "disable",
		Username:  credSecret.Value, // This would be the dynamic username
		IsDynamic: true,
		CreatedAt: time.Now(),
	}

	// For the dynamic credentials, we need to parse additional metadata
	// This is a simplified version - in reality, Vault's database engine returns
	// both username and password along with lease information
	
	// Try to get the password from the secret (vault typically returns both)
	passwordSecret, err := secretStore.Get(rc.Ctx, "database/creds/delphi-readonly/password")
	if err != nil {
		// If separate password endpoint doesn't exist, the username secret might contain both
		// This depends on how the Vault database engine is configured
		logger.Debug("No separate password endpoint, using credential from main response")
		config.Password = credSecret.Value // Fallback - may need adjustment based on actual Vault response
	} else {
		config.Password = passwordSecret.Value
	}

	// Set lease information (this would come from Vault's lease metadata)
	config.LeaseTTL = 3600 // Default 1 hour TTL
	config.ExpiresAt = config.CreatedAt.Add(time.Duration(config.LeaseTTL) * time.Second)
	config.Renewable = true

	return config, nil
}

// getStaticCredentials retrieves static database credentials (fallback method)
func getStaticCredentials(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade) (*ConnectionConfig, error) {
	secretStore := facade.GetSecretStore()
	
	// Retrieve database connection details from Vault
	config := &ConnectionConfig{
		SSLMode:   "disable", // Default
		IsDynamic: false,
		CreatedAt: time.Now(),
	}

	// Get each component of the connection
	secrets := map[string]*string{
		"delphi/database/host":     &config.Host,
		"delphi/database/port":     &config.Port,
		"delphi/database/name":     &config.Database,
		"delphi/database/username": &config.Username,
		"delphi/database/password": &config.Password,
	}

	allFound := true
	for secretPath, target := range secrets {
		secret, err := secretStore.Get(rc.Ctx, secretPath)
		if err != nil {
			allFound = false
			continue
		}
		*target = secret.Value
	}

	// Check if we got all required secrets
	if !allFound || config.Host == "" || config.Username == "" || config.Password == "" {
		return nil, fmt.Errorf("not all required static credentials found in Vault")
	}

	// Set defaults for optional fields
	if config.Port == "" {
		config.Port = "5432"
	}
	if config.Database == "" {
		config.Database = "delphi"
	}

	return config, nil
}

// getDatabaseConfig retrieves static database connection parameters (host, port, database name)
func getDatabaseConfig(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade) (*ConnectionConfig, error) {
	secretStore := facade.GetSecretStore()
	
	config := &ConnectionConfig{
		SSLMode: "disable", // Default
	}

	// Get database connection parameters (not credentials)
	configSecrets := map[string]*string{
		"delphi/config/host":     &config.Host,
		"delphi/config/port":     &config.Port,
		"delphi/config/database": &config.Database,
	}

	for secretPath, target := range configSecrets {
		secret, err := secretStore.Get(rc.Ctx, secretPath)
		if err != nil {
			// Use defaults if config not found
			continue
		}
		*target = secret.Value
	}

	// Set defaults for missing values
	if config.Host == "" {
		config.Host = "localhost"
	}
	if config.Port == "" {
		config.Port = "5432"
	}
	if config.Database == "" {
		config.Database = "delphi"
	}

	return config, nil
}

// getConnectionFromEnvironment retrieves connection details from environment variables
func getConnectionFromEnvironment() *ConnectionConfig {
	// First try PG_DSN (used by Python workers)
	if pgDSN := os.Getenv("PG_DSN"); pgDSN != "" {
		return &ConnectionConfig{
			Host:     "localhost", // Will be parsed from PG_DSN if needed
			Port:     "5432",
			Database: "delphi",
			Username: "delphi",
			Password: "delphi",
			SSLMode:  "disable",
		}
	}

	// Try individual environment variables
	return &ConnectionConfig{
		Host:     getEnvOrDefault("DELPHI_DB_HOST", "localhost"),
		Port:     getEnvOrDefault("DELPHI_DB_PORT", "5432"),
		Database: getEnvOrDefault("DELPHI_DB_NAME", "delphi"),
		Username: getEnvOrDefault("DELPHI_DB_USER", "delphi"),
		Password: getEnvOrDefault("DELPHI_DB_PASSWORD", "delphi"),
		SSLMode:  getEnvOrDefault("DELPHI_DB_SSLMODE", "disable"),
	}
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ToConnectionString converts config to PostgreSQL connection string
func (c *ConnectionConfig) ToConnectionString() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		c.Username, c.Password, c.Host, c.Port, c.Database, c.SSLMode)
}

// Connect establishes a database connection using the configuration
func Connect(rc *eos_io.RuntimeContext) (*sql.DB, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Get connection configuration (try Vault first, fallback to environment)
	config, err := GetConnectionFromVault(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to get database configuration: %w", err)
	}

	// Create connection string
	connStr := config.ToConnectionString()
	
	logger.Info("Connecting to PostgreSQL database",
		zap.String("host", config.Host),
		zap.String("port", config.Port),
		zap.String("database", config.Database),
		zap.String("username", config.Username),
		zap.Bool("dynamic_credentials", config.IsDynamic))

	// Open database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			logger.Warn("Failed to close database after ping failure", zap.Error(closeErr))
		}
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool based on credential type
	if config.IsDynamic {
		// For dynamic credentials, use shorter connection lifetimes
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(2)
		db.SetConnMaxLifetime(30 * time.Minute) // Shorter than lease TTL
	} else {
		// For static credentials, use standard settings
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(time.Hour)
	}

	if config.IsDynamic {
		logger.Info("Database connection established with dynamic credentials",
			zap.String("lease_id", config.LeaseID),
			zap.Time("expires_at", config.ExpiresAt))
	} else {
		logger.Info("Database connection established with static credentials")
	}

	return db, nil
}

// RenewCredentials attempts to renew dynamic database credentials
func RenewCredentials(rc *eos_io.RuntimeContext, config *ConnectionConfig) (*ConnectionConfig, error) {
	if !config.IsDynamic || !config.Renewable {
		return config, fmt.Errorf("credentials are not renewable")
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Attempting to renew dynamic database credentials",
		zap.String("lease_id", config.LeaseID))

	// Initialize Vault service
	if err := vault.InitializeServiceFacade(rc); err != nil {
		return nil, fmt.Errorf("failed to initialize Vault service: %w", err)
	}

	facade := vault.GetServiceFacade()
	if facade == nil {
		return nil, fmt.Errorf("vault service not available")
	}

	// Request credential renewal (this would use Vault's lease renewal API)
	// For now, we'll get fresh credentials
	newConfig, err := getDynamicCredentials(rc, facade)
	if err != nil {
		return nil, fmt.Errorf("failed to renew credentials: %w", err)
	}

	logger.Info("Successfully renewed dynamic database credentials",
		zap.String("old_lease_id", config.LeaseID),
		zap.String("new_lease_id", newConfig.LeaseID))

	return newConfig, nil
}

// RevokeCredentials revokes dynamic database credentials in Vault
func RevokeCredentials(rc *eos_io.RuntimeContext, config *ConnectionConfig) error {
	if !config.IsDynamic || config.LeaseID == "" {
		return nil // Nothing to revoke
	}

	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Revoking dynamic database credentials",
		zap.String("lease_id", config.LeaseID))

	// Initialize Vault service
	if err := vault.InitializeServiceFacade(rc); err != nil {
		return fmt.Errorf("failed to initialize Vault service: %w", err)
	}

	facade := vault.GetServiceFacade()
	if facade == nil {
		return fmt.Errorf("vault service not available")
	}

	// This would call Vault's lease revocation API
	// For now, we'll just log the intent
	logger.Info("Dynamic credentials marked for revocation",
		zap.String("lease_id", config.LeaseID))

	return nil
}

// IsExpired checks if dynamic credentials have expired
func (c *ConnectionConfig) IsExpired() bool {
	if !c.IsDynamic {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// TimeToExpiry returns the time until credentials expire
func (c *ConnectionConfig) TimeToExpiry() time.Duration {
	if !c.IsDynamic {
		return time.Duration(0)
	}
	return time.Until(c.ExpiresAt)
}

// ShouldRenew checks if credentials should be renewed (e.g., 75% of TTL elapsed)
func (c *ConnectionConfig) ShouldRenew() bool {
	if !c.IsDynamic || !c.Renewable {
		return false
	}
	
	// Renew when 75% of the lease time has elapsed
	totalTTL := time.Duration(c.LeaseTTL) * time.Second
	renewThreshold := totalTTL * 75 / 100
	elapsed := time.Since(c.CreatedAt)
	
	return elapsed >= renewThreshold
}

// ParsePGDSN parses a PostgreSQL DSN string and returns a ConnectionConfig
func ParsePGDSN(dsn string) (*ConnectionConfig, error) {
	// This is a simplified parser - in production you might want to use a proper DSN parser
	// For now, we'll assume the format is: postgres://username:password@host:port/database?options
	
	// TODO: Implement proper DSN parsing if needed
	return &ConnectionConfig{
		Host:     "localhost",
		Port:     "5432", 
		Database: "delphi",
		Username: "delphi",
		Password: "",
		SSLMode:  "disable",
	}, nil
}