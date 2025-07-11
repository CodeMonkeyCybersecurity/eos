package secrets

import (
	"bufio"
	"fmt"
	"strings"
	"syscall"
	"time"

	vaultDomain "github.com/CodeMonkeyCybersecurity/eos/pkg/domain/vault"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"golang.org/x/term"
)

// SetDatabaseConfig sets database connection parameters (not credentials)
// Migrated from cmd/self/secrets.go setDatabaseConfig
func SetDatabaseConfig(rc *eos_io.RuntimeContext, secretStore vaultDomain.SecretStore, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for database configuration setup
	logger.Info("Assessing database configuration setup")
	fmt.Printf("\n🗄️  Database Connection Configuration\n")
	fmt.Printf("====================================\n")
	fmt.Printf("This sets connection parameters for the PostgreSQL database.\n")
	fmt.Printf("For dynamic credentials, this should point to the guest VM database.\n\n")

	// INTERVENE - Collect database configuration parameters
	fmt.Printf("Database host [localhost]: ")
	host, _ := reader.ReadString('\n')
	host = strings.TrimSpace(host)
	if host == "" {
		host = "localhost"
	}

	fmt.Printf("Database port [5432]: ")
	port, _ := reader.ReadString('\n')
	port = strings.TrimSpace(port)
	if port == "" {
		port = "5432"
	}

	fmt.Printf("Database name [delphi]: ")
	dbname, _ := reader.ReadString('\n')
	dbname = strings.TrimSpace(dbname)
	if dbname == "" {
		dbname = "delphi"
	}

	// Store configuration secrets in Vault
	secrets := map[string]string{
		"delphi/config/host":     host,
		"delphi/config/port":     port,
		"delphi/config/database": dbname,
	}

	for key, value := range secrets {
		secret := &vaultDomain.Secret{
			Key:       key,
			Value:     value,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := secretStore.Set(rc.Ctx, key, secret); err != nil {
			logger.Error("Failed to store configuration secret",
				zap.String("key", key),
				zap.Error(err))
			return fmt.Errorf("failed to store %s: %w", key, err)
		}
	}

	// EVALUATE - Log success and provide next steps
	logger.Info("Database configuration stored successfully")
	fmt.Printf("✅ Database configuration stored successfully\n")
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("- Set up database engine: eos self secrets set delphi-db-engine\n")
	fmt.Printf("- Or set static credentials: eos self secrets set delphi-db\n")
	return nil
}

// SetupDatabaseEngine guides the user through setting up Vault's database secrets engine
// Migrated from cmd/self/secrets.go setupDatabaseEngine
func SetupDatabaseEngine(rc *eos_io.RuntimeContext, reader *bufio.Reader) error {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare for database engine setup
	logger.Info("Assessing database secrets engine setup")
	fmt.Printf("\n🏗️  Vault Database Secrets Engine Setup\n")
	fmt.Printf("=======================================\n")
	fmt.Printf("This will guide you through configuring Vault's database secrets engine\n")
	fmt.Printf("for dynamic PostgreSQL credential generation.\n\n")

	fmt.Printf("⚠️  IMPORTANT: This requires PostgreSQL admin access on the target database.\n")
	fmt.Printf("The database should be running in your guest VM.\n\n")

	// INTERVENE - Collect database admin credentials and configuration
	fmt.Printf("Database admin username (e.g., postgres): ")
	adminUser, _ := reader.ReadString('\n')
	adminUser = strings.TrimSpace(adminUser)
	if adminUser == "" {
		logger.Error("Admin username is required")
		return fmt.Errorf("admin username is required")
	}

	fmt.Printf("Database admin password: ")
	adminPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read admin password", zap.Error(err))
		return fmt.Errorf("failed to read admin password: %w", err)
	}
	fmt.Printf("\n")

	fmt.Printf("Database host (guest VM IP, e.g., 100.88.69.11): ")
	dbHost, _ := reader.ReadString('\n')
	dbHost = strings.TrimSpace(dbHost)
	if dbHost == "" {
		dbHost = "localhost"
	}

	fmt.Printf("Database port [5432]: ")
	dbPort, _ := reader.ReadString('\n')
	dbPort = strings.TrimSpace(dbPort)
	if dbPort == "" {
		dbPort = "5432"
	}

	fmt.Printf("Database name [delphi]: ")
	dbName, _ := reader.ReadString('\n')
	dbName = strings.TrimSpace(dbName)
	if dbName == "" {
		dbName = "delphi"
	}

	// EVALUATE - Generate configuration commands and provide setup instructions
	logger.Info("Generating Vault database engine configuration commands",
		zap.String("host", dbHost),
		zap.String("port", dbPort),
		zap.String("database", dbName),
		zap.String("admin_user", adminUser))

	fmt.Printf("\n📋 Configuration Summary:\n")
	fmt.Printf("  Host: %s:%s\n", dbHost, dbPort)
	fmt.Printf("  Database: %s\n", dbName)
	fmt.Printf("  Admin User: %s\n", adminUser)
	fmt.Printf("  Dynamic Role: delphi-readonly\n\n")

	fmt.Printf("🔧 To complete the setup, run these Vault commands on your host:\n\n")

	// Generate the Vault commands for the user
	fmt.Printf("# Enable the database secrets engine\n")
	fmt.Printf("vault secrets enable database\n\n")

	fmt.Printf("# Configure the PostgreSQL connection\n")
	fmt.Printf("vault write database/config/delphi-postgresql \\\\\n")
	fmt.Printf("    plugin_name=postgresql-database-plugin \\\\\n")
	fmt.Printf("    connection_url=\"postgresql://{{username}}:{{password}}@%s:%s/%s?sslmode=disable\" \\\\\n", dbHost, dbPort, dbName)
	fmt.Printf("    allowed_roles=\"delphi-readonly\" \\\\\n")
	fmt.Printf("    username=\"%s\" \\\\\n", adminUser)
	fmt.Printf("    password=\"%s\"\n\n", string(adminPassword))

	fmt.Printf("# Create a read-only role for the Delphi application\n")
	fmt.Printf("vault write database/roles/delphi-readonly \\\\\n")
	fmt.Printf("    db_name=delphi-postgresql \\\\\n")
	fmt.Printf("    creation_statements=\"CREATE ROLE \\\"{{name}}\\\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \\\\\n")
	fmt.Printf("                          GRANT CONNECT ON DATABASE %s TO \\\"{{name}}\\\"; \\\\\n", dbName)
	fmt.Printf("                          GRANT USAGE ON SCHEMA public TO \\\"{{name}}\\\"; \\\\\n")
	fmt.Printf("                          GRANT SELECT ON ALL TABLES IN SCHEMA public TO \\\"{{name}}\\\"; \\\\\n")
	fmt.Printf("                          ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \\\"{{name}}\\\";\" \\\\\n")
	fmt.Printf("    default_ttl=\"1h\" \\\\\n")
	fmt.Printf("    max_ttl=\"24h\"\n\n")

	fmt.Printf("# Test the configuration\n")
	fmt.Printf("vault read database/creds/delphi-readonly\n\n")

	fmt.Printf("✅ After running these commands:\n")
	fmt.Printf("- Test with: eos self secrets test\n")
	fmt.Printf("- Run dashboard: eos delphi dashboard\n")
	fmt.Printf("- The dashboard will automatically use dynamic credentials\n\n")

	logger.Info("Database secrets engine setup instructions generated successfully")
	fmt.Printf("📋 Setup instructions generated successfully\n")
	return nil
}