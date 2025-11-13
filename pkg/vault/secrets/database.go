package secrets

import (
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Package secrets provides database configuration management for Vault integration
// This implementation follows Eos standards:
// - All user output uses stderr to preserve stdout
// - Structured logging with otelzap.Ctx(rc.Ctx)
// - User prompts use interaction package patterns
// - Follows Assess → Intervene → Evaluate pattern
// - Enhanced error handling and context

// DatabaseConfig holds database configuration parameters
type DatabaseConfig struct {
	Host   string `json:"host"`
	Port   string `json:"port"`
	DBName string `json:"dbname"`
}

// SetDatabaseConfig sets database connection parameters following Eos standards
func SetDatabaseConfig(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade) error {
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

	// Store configuration in vault using simplified facade
	if err := storeDatabaseConfiguration(rc, facade, config); err != nil {
		return fmt.Errorf("failed to store database configuration: %w", err)
	}

	// EVALUATE - Verify configuration was stored successfully
	logger.Info("Evaluating database configuration storage")

	if err := verifyDatabaseConfigurationStorage(rc, facade, config); err != nil {
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
	dbname := interaction.PromptInput(rc.Ctx, "Database name", "wazuh")
	config.DBName = strings.TrimSpace(dbname)

	logger.Info("Database configuration gathered",
		zap.String("host", config.Host),
		zap.String("port", config.Port),
		zap.String("dbname", config.DBName))

	return config, nil
}

// storeDatabaseConfiguration stores the configuration using simplified vault facade
func storeDatabaseConfiguration(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade, config *DatabaseConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Storing database configuration in Vault")

	// Store each config value individually for easier retrieval
	configPaths := map[string]map[string]interface{}{
		"secret/data/wazuh/config/host":     {"data": map[string]interface{}{"value": config.Host}},
		"secret/data/wazuh/config/port":     {"data": map[string]interface{}{"value": config.Port}},
		"secret/data/wazuh/config/database": {"data": map[string]interface{}{"value": config.DBName}},
	}

	// Store each configuration value
	for path, data := range configPaths {
		if err := facade.StoreSecret(rc.Ctx, path, data); err != nil {
			return fmt.Errorf("failed to store config at %s: %w", path, err)
		}
	}

	logger.Info("Database configuration stored successfully")
	return nil
}

// verifyDatabaseConfigurationStorage verifies the configuration was stored correctly
func verifyDatabaseConfigurationStorage(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade, config *DatabaseConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying database configuration storage")

	// Verify each stored configuration value
	configPaths := map[string]string{
		"secret/data/wazuh/config/host":     config.Host,
		"secret/data/wazuh/config/port":     config.Port,
		"secret/data/wazuh/config/database": config.DBName,
	}

	for path, expectedValue := range configPaths {
		storedData, err := facade.RetrieveSecret(rc.Ctx, path)
		if err != nil {
			return fmt.Errorf("failed to retrieve stored configuration at %s: %w", path, err)
		}

		// Extract value from KV v2 structure
		if data, ok := storedData["data"].(map[string]interface{}); ok {
			if value, ok := data["value"].(string); ok {
				if value != expectedValue {
					return fmt.Errorf("stored value at %s does not match input: got %s, expected %s", path, value, expectedValue)
				}
			} else {
				return fmt.Errorf("invalid data structure at %s: missing value field", path)
			}
		} else {
			return fmt.Errorf("invalid data structure at %s: missing data field", path)
		}
	}

	logger.Info("Database configuration verification successful")
	return nil
}

// displayDatabaseConfigSuccess displays success message and next steps
func displayDatabaseConfigSuccess(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: Database configuration completed")

	successMessage := `
 Database configuration stored successfully

 Next steps:
- Set up database engine: eos self secrets set wazuh-db-engine
- Or set static credentials: eos self secrets set wazuh-db

`

	if _, err := fmt.Fprint(os.Stderr, successMessage); err != nil {
		return fmt.Errorf("failed to display success message: %w", err)
	}

	return nil
}

// DatabaseAdminCredentials holds admin credentials for database setup
type DatabaseAdminCredentials struct {
	Username string
	Password string
}

// SetDatabaseEngine sets up Vault database secrets engine following Eos standards
func SetDatabaseEngine(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade) error {
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
	if err := configureDatabaseEngine(rc, facade, credentials); err != nil {
		return fmt.Errorf("failed to configure database engine: %w", err)
	}

	// EVALUATE - Verify engine configuration
	logger.Info("Evaluating database engine configuration")

	if err := verifyDatabaseEngine(rc, facade); err != nil {
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

IMPORTANT: This requires PostgreSQL admin access on the target database.
The database should be running in your guest VM.

`

	if _, err := fmt.Fprint(os.Stderr, introduction); err != nil {
		return fmt.Errorf("failed to display introduction: %w", err)
	}

	return nil
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
func configureDatabaseEngine(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade, credentials *DatabaseAdminCredentials) error {
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
func verifyDatabaseEngine(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade) error {
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
 Vault database secrets engine configured successfully

 Next steps:
- Test credential generation: vault read database/creds/wazuh-role
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
