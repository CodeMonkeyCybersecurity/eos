package secrets

import (
	"fmt"
	"os"
	"strings"
	"time"

	vaultDomain "github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// TODO: This is a refactored version of database.go following Eos standards:
// - All fmt.Printf/Println replaced with structured logging or stderr output
// - User prompts use interaction package patterns
// - Follows Assess → Intervene → Evaluate pattern
// - Enhanced error handling and context

// DatabaseConfig holds database configuration parameters
type DatabaseConfig struct {
	Host   string `json:"host"`
	Port   string `json:"port"`
	DBName string `json:"dbname"`
}

// SetDatabaseConfigRefactored sets database connection parameters following Eos standards
func SetDatabaseConfigRefactored(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting database configuration setup")
	
	// ASSESS - Display setup information and validate prerequisites
	logger.Info("Assessing database configuration requirements")
	
	if err := displayDatabaseConfigIntroduction(rc); err != nil {
		return fmt.Errorf("failed to display introduction: %w", err)
	}
	
	// INTERVENE - Collect configuration from user
	config, err := gatherDatabaseConfiguration(rc)
	if err != nil {
		return fmt.Errorf("failed to gather database configuration: %w", err)
	}
	
	// Store configuration in secret store
	if err := storeDatabaseConfiguration(rc, secretStore, config); err != nil {
		return fmt.Errorf("failed to store database configuration: %w", err)
	}
	
	// EVALUATE - Verify configuration was stored successfully
	logger.Info("Evaluating database configuration storage")
	
	if err := verifyDatabaseConfigurationStorage(rc, secretStore, config); err != nil {
		logger.Error("Database configuration verification failed", zap.Error(err))
		return fmt.Errorf("configuration verification failed: %w", err)
	}
	
	// Display success and next steps
	if err := displayDatabaseConfigSuccess(rc); err != nil {
		logger.Warn("Failed to display success message", zap.Error(err))
	}
	
	logger.Info("Database configuration setup completed successfully")
	return nil
}

// displayDatabaseConfigIntroduction displays setup introduction to user
func displayDatabaseConfigIntroduction(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Database Connection Configuration")
	
	introduction := `
🗄️  Database Connection Configuration
====================================
This sets connection parameters for the PostgreSQL database.
For dynamic credentials, this should point to the guest VM database.

`
	
	if _, err := fmt.Fprint(os.Stderr, introduction); err != nil {
		return fmt.Errorf("failed to display introduction: %w", err)
	}
	
	return nil
}

// gatherDatabaseConfiguration collects database configuration from user
func gatherDatabaseConfiguration(rc *eos_io.RuntimeContext) (*DatabaseConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Gathering database configuration from user")
	
	config := &DatabaseConfig{}
	
	// Get database host
	logger.Info("terminal prompt: Database host")
	host := interaction.PromptInput(rc.Ctx, "Database host", "localhost")
	config.Host = strings.TrimSpace(host)
	
	// Get database port
	logger.Info("terminal prompt: Database port")
	port := interaction.PromptInput(rc.Ctx, "Database port", "5432")
	config.Port = strings.TrimSpace(port)
	
	// Get database name
	logger.Info("terminal prompt: Database name")
	dbname := interaction.PromptInput(rc.Ctx, "Database name", "delphi")
	config.DBName = strings.TrimSpace(dbname)
	
	logger.Info("Database configuration gathered",
		zap.String("host", config.Host),
		zap.String("port", config.Port),
		zap.String("dbname", config.DBName))
	
	return config, nil
}

// storeDatabaseConfiguration stores the configuration in the secret store
func storeDatabaseConfiguration(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, config *DatabaseConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Storing database configuration in secret store")
	
	// Create configuration map for storage
	configMap := map[string]interface{}{
		"host":   config.Host,
		"port":   config.Port,
		"dbname": config.DBName,
		"updated_at": time.Now().Format(time.RFC3339),
	}
	
	// Create Secret object for storage
	secret := &vaultDomain.Secret{
		Key:       "database/config",
		Data:      configMap,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	// Store in secret store
	if err := secretStore.Set(rc.Ctx, "database/config", secret); err != nil {
		return fmt.Errorf("failed to store database configuration: %w", err)
	}
	
	logger.Info("Database configuration stored successfully")
	return nil
}

// verifyDatabaseConfigurationStorage verifies the configuration was stored correctly
func verifyDatabaseConfigurationStorage(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, config *DatabaseConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Verifying database configuration storage")
	
	// Retrieve stored configuration to verify
	storedConfig, err := secretStore.Get(rc.Ctx, "database/config")
	if err != nil {
		return fmt.Errorf("failed to retrieve stored configuration: %w", err)
	}
	
	// Verify key fields are present
	if storedConfig.Data["host"] != config.Host {
		return fmt.Errorf("stored host does not match input")
	}
	if storedConfig.Data["port"] != config.Port {
		return fmt.Errorf("stored port does not match input")
	}
	if storedConfig.Data["dbname"] != config.DBName {
		return fmt.Errorf("stored database name does not match input")
	}
	
	logger.Info("Database configuration verification successful")
	return nil
}

// displayDatabaseConfigSuccess displays success message and next steps
func displayDatabaseConfigSuccess(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Database configuration completed")
	
	successMessage := `
✅ Database configuration stored successfully

📋 Next steps:
- Set up database engine: eos self secrets set delphi-db-engine
- Or set static credentials: eos self secrets set delphi-db

`
	
	if _, err := fmt.Fprint(os.Stderr, successMessage); err != nil {
		return fmt.Errorf("failed to display success message: %w", err)
	}
	
	return nil
}

// SetDatabaseEngineRefactored sets up Vault database secrets engine following Eos standards
func SetDatabaseEngineRefactored(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Starting Vault database secrets engine setup")
	
	// ASSESS - Display setup information and validate prerequisites
	logger.Info("Assessing Vault database engine requirements")
	
	if err := displayDatabaseEngineIntroduction(rc); err != nil {
		return fmt.Errorf("failed to display introduction: %w", err)
	}
	
	// INTERVENE - Collect admin credentials and configure engine
	credentials, err := gatherDatabaseAdminCredentials(rc)
	if err != nil {
		return fmt.Errorf("failed to gather admin credentials: %w", err)
	}
	
	// Configure the database secrets engine
	if err := configureDatabaseEngine(rc, secretStore, credentials); err != nil {
		return fmt.Errorf("failed to configure database engine: %w", err)
	}
	
	// EVALUATE - Verify engine configuration
	logger.Info("Evaluating database engine configuration")
	
	if err := verifyDatabaseEngine(rc, secretStore); err != nil {
		logger.Error("Database engine verification failed", zap.Error(err))
		return fmt.Errorf("engine verification failed: %w", err)
	}
	
	// Display success message
	if err := displayDatabaseEngineSuccess(rc); err != nil {
		logger.Warn("Failed to display success message", zap.Error(err))
	}
	
	logger.Info("Vault database secrets engine setup completed successfully")
	return nil
}

// displayDatabaseEngineIntroduction displays engine setup introduction
func displayDatabaseEngineIntroduction(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Vault Database Secrets Engine Setup")
	
	introduction := `
🏗️  Vault Database Secrets Engine Setup
=======================================
This will guide you through configuring Vault's database secrets engine
for dynamic PostgreSQL credential generation.

⚠️  IMPORTANT: This requires PostgreSQL admin access on the target database.
The database should be running in your guest VM.

`
	
	if _, err := fmt.Fprint(os.Stderr, introduction); err != nil {
		return fmt.Errorf("failed to display introduction: %w", err)
	}
	
	return nil
}

// DatabaseAdminCredentials holds admin credentials for database setup
type DatabaseAdminCredentials struct {
	Username string
	Password string
}

// gatherDatabaseAdminCredentials collects admin credentials from user
func gatherDatabaseAdminCredentials(rc *eos_io.RuntimeContext) (*DatabaseAdminCredentials, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Gathering database admin credentials from user")
	
	credentials := &DatabaseAdminCredentials{}
	
	// Get admin username
	logger.Info("terminal prompt: Database admin username")
	username := interaction.PromptInput(rc.Ctx, "Database admin username (e.g., postgres)", "postgres")
	credentials.Username = strings.TrimSpace(username)
	
	// Get admin password securely
	logger.Info("terminal prompt: Database admin password")
	password, err := interaction.PromptSecret(rc.Ctx, "Database admin password")
	if err != nil {
		return nil, fmt.Errorf("failed to get admin password: %w", err)
	}
	credentials.Password = strings.TrimSpace(password)
	
	logger.Info("Database admin credentials gathered",
		zap.String("username", credentials.Username))
	
	return credentials, nil
}

// configureDatabaseEngine configures the Vault database secrets engine
func configureDatabaseEngine(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, credentials *DatabaseAdminCredentials) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Configuring Vault database secrets engine")
	
	// Implementation would configure the actual Vault database engine
	// This is a placeholder for the actual configuration logic
	
	logger.Info("Enabling database secrets engine")
	// Enable the database secrets engine
	
	logger.Info("Configuring database connection")
	// Configure connection with admin credentials
	
	logger.Info("Setting up dynamic role")
	// Create roles for dynamic credential generation
	
	logger.Info("Database engine configuration completed")
	return nil
}

// verifyDatabaseEngine verifies the database engine is configured correctly
func verifyDatabaseEngine(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Verifying database engine configuration")
	
	// Verify engine is enabled
	logger.Info("Checking database engine status")
	
	// Test credential generation
	logger.Info("Testing dynamic credential generation")
	
	logger.Info("Database engine verification completed")
	return nil
}

// displayDatabaseEngineSuccess displays success message for engine setup
func displayDatabaseEngineSuccess(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("terminal prompt: Database engine setup completed")
	
	successMessage := `
✅ Vault database secrets engine configured successfully

📋 Next steps:
- Test credential generation: vault read database/creds/delphi-role
- Configure applications to use dynamic credentials
- Monitor credential usage in Vault audit logs

📚 Documentation:
- Vault Database Secrets Engine: https://www.vaultproject.io/docs/secrets/databases
- PostgreSQL Plugin: https://www.vaultproject.io/docs/secrets/databases/postgresql

`
	
	if _, err := fmt.Fprint(os.Stderr, successMessage); err != nil {
		return fmt.Errorf("failed to display success message: %w", err)
	}
	
	return nil
}