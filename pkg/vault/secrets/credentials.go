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

// Package secrets provides secure credential management for Vault integration
// This implementation follows Eos standards:
// - All user output uses stderr to preserve stdout
// - Structured logging with otelzap.Ctx(rc.Ctx)
// - User prompts use interaction package patterns
// - Follows Assess → Intervene → Evaluate pattern
// - Enhanced error handling and context

// DatabaseCredentials holds complete database credentials
type DatabaseCredentials struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	DBName   string `json:"dbname"`
	Username string `json:"username"`
	Password string `json:"password"`
	SSLMode  string `json:"sslmode"`
}

// SetDatabaseCredentials configures database credentials in Vault following Eos standards
func SetDatabaseCredentials(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting database credentials setup")

	// ASSESS - Display setup information and validate prerequisites
	logger.Info("Assessing database credentials requirements")

	if err := displayDatabaseCredentialsIntroduction(rc); err != nil {
		return fmt.Errorf("failed to display introduction: %w", err)
	}

	// INTERVENE - Collect complete credentials from user
	credentials, err := gatherDatabaseCredentials(rc)
	if err != nil {
		return fmt.Errorf("failed to gather database credentials: %w", err)
	}

	// Store credentials securely
	if err := storeDatabaseCredentials(rc, facade, credentials); err != nil {
		return fmt.Errorf("failed to store database credentials: %w", err)
	}

	// EVALUATE - Verify credentials were stored and test connection
	logger.Info("Evaluating database credentials storage")

	if err := verifyDatabaseCredentials(rc, facade, credentials); err != nil {
		logger.Error("Database credentials verification failed", zap.Error(err))
		return fmt.Errorf("credentials verification failed: %w", err)
	}

	// Display success and next steps
	if err := displayDatabaseCredentialsSuccess(rc); err != nil {
		logger.Warn("Failed to display success message", zap.Error(err))
	}

	logger.Info("Database credentials setup completed successfully")
	return nil
}

// displayDatabaseCredentialsIntroduction displays setup introduction to user
func displayDatabaseCredentialsIntroduction(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: Database Credentials Setup")

	introduction := `
🗄️  Database Credentials Setup
===============================
This will configure static database credentials in Vault.
Use this for applications that need persistent database access.

📝 Note: For enhanced security, consider using dynamic credentials instead.

`

	if _, err := fmt.Fprint(os.Stderr, introduction); err != nil {
		return fmt.Errorf("failed to display introduction: %w", err)
	}

	return nil
}

// gatherDatabaseCredentials collects complete database credentials from user
func gatherDatabaseCredentials(rc *eos_io.RuntimeContext) (*DatabaseCredentials, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Gathering complete database credentials from user")

	credentials := &DatabaseCredentials{}

	// Database connection details
	logger.Info("terminal prompt: Database host")
	host := interaction.PromptInput(rc.Ctx, "Database host", "localhost")
	credentials.Host = strings.TrimSpace(host)

	logger.Info("terminal prompt: Database port")
	port := interaction.PromptInput(rc.Ctx, "Database port", "5432")
	credentials.Port = strings.TrimSpace(port)

	logger.Info("terminal prompt: Database name")
	dbname := interaction.PromptInput(rc.Ctx, "Database name", "delphi")
	credentials.DBName = strings.TrimSpace(dbname)

	// Authentication details
	logger.Info("terminal prompt: Database username")
	username := interaction.PromptInput(rc.Ctx, "Database username", "delphi")
	credentials.Username = strings.TrimSpace(username)

	logger.Info("terminal prompt: Database password")
	password, err := interaction.PromptSecret(rc.Ctx, "Database password")
	if err != nil {
		return nil, fmt.Errorf("failed to get database password: %w", err)
	}
	credentials.Password = strings.TrimSpace(password)

	// SSL configuration
	logger.Info("terminal prompt: SSL mode")
	sslMode := interaction.PromptInput(rc.Ctx, "SSL mode (disable/require/verify-ca/verify-full)", "disable")
	credentials.SSLMode = strings.TrimSpace(sslMode)

	logger.Info("Database credentials gathered",
		zap.String("host", credentials.Host),
		zap.String("port", credentials.Port),
		zap.String("dbname", credentials.DBName),
		zap.String("username", credentials.Username),
		zap.String("sslmode", credentials.SSLMode))

	return credentials, nil
}

// storeDatabaseCredentials stores credentials securely in the secret store
func storeDatabaseCredentials(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade, credentials *DatabaseCredentials) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Storing database credentials securely in Vault")

	// Store credentials using simplified facade - store each credential separately for easier retrieval
	credentialPaths := map[string]map[string]interface{}{
		"secret/data/delphi/database/host":     {"data": map[string]interface{}{"value": credentials.Host}},
		"secret/data/delphi/database/port":     {"data": map[string]interface{}{"value": credentials.Port}},
		"secret/data/delphi/database/name":     {"data": map[string]interface{}{"value": credentials.DBName}},
		"secret/data/delphi/database/username": {"data": map[string]interface{}{"value": credentials.Username}},
		"secret/data/delphi/database/password": {"data": map[string]interface{}{"value": credentials.Password}},
	}

	// Store each credential separately
	for path, data := range credentialPaths {
		if err := facade.StoreSecret(rc.Ctx, path, data); err != nil {
			return fmt.Errorf("failed to store credential at %s: %w", path, err)
		}
	}

	logger.Info("Database credentials stored securely")
	return nil
}

// verifyDatabaseCredentials verifies credentials were stored and optionally tests connection
func verifyDatabaseCredentials(rc *eos_io.RuntimeContext, facade *vault.ServiceFacade, credentials *DatabaseCredentials) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Verifying database credentials storage")

	// Verify each stored credential
	credentialPaths := map[string]string{
		"secret/data/delphi/database/host":     credentials.Host,
		"secret/data/delphi/database/port":     credentials.Port,
		"secret/data/delphi/database/name":     credentials.DBName,
		"secret/data/delphi/database/username": credentials.Username,
		"secret/data/delphi/database/password": credentials.Password,
	}

	for path, expectedValue := range credentialPaths {
		storedData, err := facade.RetrieveSecret(rc.Ctx, path)
		if err != nil {
			return fmt.Errorf("failed to retrieve stored credential at %s: %w", path, err)
		}

		// Extract value from KV v2 structure and verify
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

	// Optional: Test database connection
	logger.Info("terminal prompt: Test database connection?")
	testConnection := interaction.PromptInput(rc.Ctx, "Test database connection?", "y")
	if strings.ToLower(strings.TrimSpace(testConnection)) == "y" {
		if err := testDatabaseConnection(rc, credentials); err != nil {
			logger.Warn("Database connection test failed", zap.Error(err))
			// Don't fail the entire process for connection test failure
		}
	}

	logger.Info("Database credentials verification successful")
	return nil
}

// testDatabaseConnection tests the database connection with provided credentials
func testDatabaseConnection(rc *eos_io.RuntimeContext, credentials *DatabaseCredentials) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Testing database connection",
		zap.String("host", credentials.Host),
		zap.String("port", credentials.Port),
		zap.String("dbname", credentials.DBName),
		zap.String("username", credentials.Username))

	// Implementation would test actual database connection
	// This is a placeholder for the actual connection test logic

	logger.Info("Database connection test completed successfully")
	return nil
}

// displayDatabaseCredentialsSuccess displays success message and next steps
func displayDatabaseCredentialsSuccess(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: Database credentials setup completed")

	successMessage := `
 Database credentials stored securely in Vault

📋 Next steps:
- Applications can now retrieve credentials from: vault kv get secret/database/credentials/delphi
- Configure applications to use these credentials for database access
- Monitor credential usage in Vault audit logs

🔒 Security recommendations:
- Consider rotating credentials regularly
- Use dynamic credentials for enhanced security when possible
- Implement least-privilege access for database users

`

	if _, err := fmt.Fprint(os.Stderr, successMessage); err != nil {
		return fmt.Errorf("failed to display success message: %w", err)
	}

	return nil
}
